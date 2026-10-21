from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.logging import log_security_event
from app.core.auth import get_current_user, get_current_user_optional, require_role, check_org_access
from app.db.session import get_db
from app.models import (
    ControlMapping,
    SecurityControl,
    FrameworkRequirement,
    Framework,
    User,
    UserRole,
    MappingApprovalStatus,
    AuditEvent
)
from app.schemas.mapping import (
    MappingCreate,
    MappingUpdate,
    MappingReview,
    MappingResponse,
    CrossFrameworkMatrixRow
)
from app.services.assessment_service import get_cross_framework_matrix

router = APIRouter(tags=["Framework Mappings"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


def format_mapping_response(mapping: ControlMapping) -> MappingResponse:
    """Helper to convert ControlMapping ORM entity into MappingResponse schema."""
    req = mapping.requirement
    ctrl = mapping.control
    fw = req.framework
    return MappingResponse(
        id=mapping.id,
        organization_id=mapping.organization_id,
        control_id=ctrl.id,
        control_code=ctrl.control_id,
        control_name=ctrl.name,
        control_status=ctrl.implementation_status.value,
        requirement_id=req.id,
        framework_code=fw.code,
        framework_name=fw.name,
        requirement_identifier=req.identifier,
        requirement_title=req.title,
        requirement_category=req.category,
        mapping_rationale=mapping.mapping_rationale,
        approval_status=mapping.approval_status,
        reviewed_by_id=mapping.reviewed_by_id,
        reviewed_by_name=mapping.reviewed_by.full_name if mapping.reviewed_by else None,
        reviewed_at=mapping.reviewed_at,
        created_at=mapping.created_at
    )


# ==============================================================================
# Module C: REST API Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/mappings", response_model=List[MappingResponse])
async def api_list_mappings(
    framework_code: Optional[str] = None,
    control_id: Optional[str] = None,
    requirement_id: Optional[int] = None,
    approval_status: Optional[MappingApprovalStatus] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists cross-framework mappings for the authenticated organization
    with optional filtering by framework, control, requirement, and approval status.
    """
    org_id = current_user.organization_id or 1
    query = db.query(ControlMapping).filter(ControlMapping.organization_id == org_id).options(
        joinedload(ControlMapping.control),
        joinedload(ControlMapping.requirement).joinedload(FrameworkRequirement.framework),
        joinedload(ControlMapping.reviewed_by)
    )

    if approval_status:
        query = query.filter(ControlMapping.approval_status == approval_status)

    if requirement_id:
        query = query.filter(ControlMapping.requirement_id == requirement_id)

    if control_id:
        if control_id.isdigit():
            query = query.filter(ControlMapping.control_id == int(control_id))
        else:
            query = query.join(SecurityControl).filter(SecurityControl.control_id == control_id.strip().upper())

    if framework_code:
        query = query.join(FrameworkRequirement).join(Framework).filter(Framework.code == framework_code.strip().upper())

    mappings = query.order_by(ControlMapping.created_at.desc()).all()
    return [format_mapping_response(m) for m in mappings]


@router.get(f"{settings.API_V1_STR}/mappings/matrix", response_model=List[CrossFrameworkMatrixRow])
async def api_cross_framework_matrix(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns the complete Cross-Framework Mapping Matrix comparing internal controls
    against SOC 2, ISO 27001, and NIST CSF side-by-side.
    """
    org_id = current_user.organization_id or 1
    return get_cross_framework_matrix(db, org_id)


@router.post(f"{settings.API_V1_STR}/mappings", response_model=MappingResponse, status_code=status.HTTP_201_CREATED)
async def api_create_mapping(
    mapping_in: MappingCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Creates a new cross-framework mapping link between an internal control
    and a framework requirement (SOC 2, ISO 27001, or NIST CSF).
    """
    org_id = current_user.organization_id or 1

    # Verify control belongs to this organization
    control = db.query(SecurityControl).filter(
        SecurityControl.id == mapping_in.control_id,
        SecurityControl.organization_id == org_id
    ).first()
    if not control:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security control with ID {mapping_in.control_id} not found in this organization."
        )

    # Verify requirement exists
    requirement = db.query(FrameworkRequirement).filter(
        FrameworkRequirement.id == mapping_in.requirement_id
    ).first()
    if not requirement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Framework requirement with ID {mapping_in.requirement_id} not found."
        )

    # Prevent duplicate mapping
    existing = db.query(ControlMapping).filter(
        ControlMapping.organization_id == org_id,
        ControlMapping.control_id == mapping_in.control_id,
        ControlMapping.requirement_id == mapping_in.requirement_id
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Control '{control.control_id}' is already mapped to requirement '{requirement.identifier}'."
        )

    # If created by Control Owner, status defaults to PROPOSED; GRC Analyst/Admin can approve directly if requested
    initial_status = mapping_in.approval_status or MappingApprovalStatus.PROPOSED
    if current_user.role == UserRole.CONTROL_OWNER:
        initial_status = MappingApprovalStatus.PROPOSED

    new_mapping = ControlMapping(
        organization_id=org_id,
        control_id=mapping_in.control_id,
        requirement_id=mapping_in.requirement_id,
        mapping_rationale=mapping_in.mapping_rationale.strip(),
        approval_status=initial_status,
        reviewed_by_id=current_user.id if initial_status == MappingApprovalStatus.APPROVED else None,
        reviewed_at=datetime.now(timezone.utc) if initial_status == MappingApprovalStatus.APPROVED else None
    )
    db.add(new_mapping)
    db.flush()

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="MAPPING_CREATED",
        resource_type="ControlMapping",
        resource_id=new_mapping.id,
        details=(
            f'{{"control_id": "{control.control_id}", "requirement": "{requirement.identifier}", '
            f'"framework": "{requirement.framework.code}", "status": "{new_mapping.approval_status.value}"}}'
        ),
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_mapping)

    log_security_event(
        event_type="MAPPING_CREATED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Mapping:{control.control_id}->{requirement.identifier}"
    )

    return format_mapping_response(new_mapping)


@router.get(f"{settings.API_V1_STR}/mappings/{{mapping_id}}", response_model=MappingResponse)
async def api_get_mapping(
    mapping_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves single mapping record by ID.
    """
    org_id = current_user.organization_id or 1
    mapping = db.query(ControlMapping).filter(
        ControlMapping.id == mapping_id,
        ControlMapping.organization_id == org_id
    ).options(
        joinedload(ControlMapping.control),
        joinedload(ControlMapping.requirement).joinedload(FrameworkRequirement.framework),
        joinedload(ControlMapping.reviewed_by)
    ).first()

    if not mapping:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mapping record not found")

    check_org_access(current_user, mapping.organization_id, request=request)
    return format_mapping_response(mapping)


@router.put(f"{settings.API_V1_STR}/mappings/{{mapping_id}}", response_model=MappingResponse)
async def api_update_mapping(
    mapping_id: int,
    update_in: MappingUpdate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Updates the rationale or approval status of an existing mapping.
    """
    org_id = current_user.organization_id or 1
    mapping = db.query(ControlMapping).filter(
        ControlMapping.id == mapping_id,
        ControlMapping.organization_id == org_id
    ).options(
        joinedload(ControlMapping.control),
        joinedload(ControlMapping.requirement).joinedload(FrameworkRequirement.framework),
        joinedload(ControlMapping.reviewed_by)
    ).first()

    if not mapping:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mapping record not found")

    check_org_access(current_user, mapping.organization_id, request=request)

    if update_in.mapping_rationale is not None:
        mapping.mapping_rationale = update_in.mapping_rationale.strip()

    if update_in.approval_status is not None:
        if current_user.role not in [UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only GRC Analysts or Administrators can change mapping approval status."
            )
        mapping.approval_status = update_in.approval_status
        mapping.reviewed_by_id = current_user.id
        mapping.reviewed_at = datetime.now(timezone.utc)

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="MAPPING_UPDATED",
        resource_type="ControlMapping",
        resource_id=mapping.id,
        details=f'{{"status": "{mapping.approval_status.value}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(mapping)

    return format_mapping_response(mapping)


@router.post(f"{settings.API_V1_STR}/mappings/{{mapping_id}}/review", response_model=MappingResponse)
async def api_review_mapping(
    mapping_id: int,
    review_in: MappingReview,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Formal GRC governance sign-off endpoint for approving or rejecting a proposed control mapping.
    Restricted to GRC Analysts and Administrators.
    """
    org_id = current_user.organization_id or 1
    mapping = db.query(ControlMapping).filter(
        ControlMapping.id == mapping_id,
        ControlMapping.organization_id == org_id
    ).options(
        joinedload(ControlMapping.control),
        joinedload(ControlMapping.requirement).joinedload(FrameworkRequirement.framework),
        joinedload(ControlMapping.reviewed_by)
    ).first()

    if not mapping:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mapping record not found")

    mapping.approval_status = review_in.approval_status
    mapping.reviewed_by_id = current_user.id
    mapping.reviewed_at = datetime.now(timezone.utc)

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="MAPPING_REVIEWED",
        resource_type="ControlMapping",
        resource_id=mapping.id,
        details=f'{{"approval_status": "{review_in.approval_status.value}", "comment": "{review_in.review_comment or ""}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(mapping)

    log_security_event(
        event_type="MAPPING_REVIEWED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Mapping:{mapping.id} -> {review_in.approval_status.value}"
    )

    return format_mapping_response(mapping)


@router.delete(f"{settings.API_V1_STR}/mappings/{{mapping_id}}", status_code=status.HTTP_204_NO_CONTENT)
async def api_delete_mapping(
    mapping_id: int,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Removes a mapping relationship between a control and a framework requirement.
    """
    org_id = current_user.organization_id or 1
    mapping = db.query(ControlMapping).filter(
        ControlMapping.id == mapping_id,
        ControlMapping.organization_id == org_id
    ).first()

    if not mapping:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mapping record not found")

    ctrl_id = mapping.control_id
    req_id = mapping.requirement_id

    db.delete(mapping)

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="MAPPING_DELETED",
        resource_type="ControlMapping",
        resource_id=mapping_id,
        details=f'{{"control_id": {ctrl_id}, "requirement_id": {req_id}}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()

    log_security_event(
        event_type="MAPPING_DELETED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Mapping:{mapping_id}",
        severity="WARNING"
    )
    return None


# ==============================================================================
# Module C: Web UI HTML Views
# ==============================================================================

@router.get("/mappings", response_class=HTMLResponse)
async def web_mappings_view(
    request: Request,
    framework: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
    view_mode: str = Query("matrix"),  # "matrix" or "list"
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Cross-Framework Mapping Engine dashboard (Module C).
    Includes side-by-side Matrix Crosswalk view and detailed Mappings Catalog.
    """
    org_id = current_user.organization_id if current_user else 1

    # Matrix data
    matrix_rows = get_cross_framework_matrix(db, org_id)

    # Detailed list query
    query = db.query(ControlMapping).filter(ControlMapping.organization_id == org_id).options(
        joinedload(ControlMapping.control),
        joinedload(ControlMapping.requirement).joinedload(FrameworkRequirement.framework),
        joinedload(ControlMapping.reviewed_by)
    )

    if framework and framework.upper() in ["SOC2", "ISO27001", "NIST_CSF"]:
        query = query.join(FrameworkRequirement).join(Framework).filter(Framework.code == framework.upper())

    if status_filter and status_filter in [s.value for s in MappingApprovalStatus]:
        query = query.filter(ControlMapping.approval_status == MappingApprovalStatus(status_filter))

    mappings = query.order_by(ControlMapping.created_at.desc()).all()

    # Dropdown helper options for modal creation
    all_controls = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id).order_by(SecurityControl.control_id).all()
    all_requirements = db.query(FrameworkRequirement).join(Framework).order_by(Framework.code, FrameworkRequirement.identifier).all()

    # Count statistics
    all_org_mappings = db.query(ControlMapping).filter(ControlMapping.organization_id == org_id).all()
    mapping_counts = {
        "ALL": len(all_org_mappings),
        "APPROVED": sum(1 for m in all_org_mappings if m.approval_status == MappingApprovalStatus.APPROVED),
        "PROPOSED": sum(1 for m in all_org_mappings if m.approval_status == MappingApprovalStatus.PROPOSED),
        "UNDER_REVIEW": sum(1 for m in all_org_mappings if m.approval_status == MappingApprovalStatus.UNDER_REVIEW),
        "REJECTED": sum(1 for m in all_org_mappings if m.approval_status == MappingApprovalStatus.REJECTED),
    }

    return templates.TemplateResponse(
        request=request,
        name="mappings.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "matrix_rows": matrix_rows,
            "mappings": mappings,
            "controls": all_controls,
            "requirements": all_requirements,
            "mapping_counts": mapping_counts,
            "active_framework": framework or "ALL",
            "active_status": status_filter or "ALL",
            "view_mode": view_mode,
            "title": "Cross-Framework Mapping Matrix | CyberGRC"
        }
    )


@router.post("/mappings", response_class=RedirectResponse)
async def web_create_mapping_form(
    request: Request,
    control_id: int = Form(...),
    requirement_id: int = Form(...),
    mapping_rationale: str = Form(...),
    approval_status: str = Form("PROPOSED"),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML modal form submission for creating a new mapping.
    """
    org_id = current_user.organization_id or 1

    # Check for duplicate
    existing = db.query(ControlMapping).filter(
        ControlMapping.organization_id == org_id,
        ControlMapping.control_id == control_id,
        ControlMapping.requirement_id == requirement_id
    ).first()

    if not existing:
        target_status = MappingApprovalStatus(approval_status)
        if current_user.role == UserRole.CONTROL_OWNER:
            target_status = MappingApprovalStatus.PROPOSED

        new_mapping = ControlMapping(
            organization_id=org_id,
            control_id=control_id,
            requirement_id=requirement_id,
            mapping_rationale=mapping_rationale.strip(),
            approval_status=target_status,
            reviewed_by_id=current_user.id if target_status == MappingApprovalStatus.APPROVED else None,
            reviewed_at=datetime.now(timezone.utc) if target_status == MappingApprovalStatus.APPROVED else None
        )
        db.add(new_mapping)
        db.commit()

    return RedirectResponse(url="/mappings?view_mode=list", status_code=status.HTTP_302_FOUND)


@router.post("/mappings/{mapping_id}/review", response_class=RedirectResponse)
async def web_review_mapping_form(
    mapping_id: int,
    request: Request,
    action: str = Form(...),  # "APPROVE" or "REJECT"
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST)),
    db: Session = Depends(get_db)
):
    """
    Processes 1-click Approve/Reject review action from web UI.
    """
    org_id = current_user.organization_id or 1
    mapping = db.query(ControlMapping).filter(
        ControlMapping.id == mapping_id,
        ControlMapping.organization_id == org_id
    ).first()

    if mapping:
        mapping.approval_status = MappingApprovalStatus.APPROVED if action == "APPROVE" else MappingApprovalStatus.REJECTED
        mapping.reviewed_by_id = current_user.id
        mapping.reviewed_at = datetime.now(timezone.utc)
        db.commit()

    return RedirectResponse(url="/mappings?view_mode=list", status_code=status.HTTP_302_FOUND)


@router.post("/mappings/{mapping_id}/delete", response_class=RedirectResponse)
async def web_delete_mapping_form(
    mapping_id: int,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST)),
    db: Session = Depends(get_db)
):
    """
    Processes delete action from web UI.
    """
    org_id = current_user.organization_id or 1
    mapping = db.query(ControlMapping).filter(
        ControlMapping.id == mapping_id,
        ControlMapping.organization_id == org_id
    ).first()

    if mapping:
        db.delete(mapping)
        db.commit()

    return RedirectResponse(url="/mappings?view_mode=list", status_code=status.HTTP_302_FOUND)
