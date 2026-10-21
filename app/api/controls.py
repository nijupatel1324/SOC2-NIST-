from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Form, Query
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.logging import log_security_event
from app.core.auth import get_current_user, get_current_user_optional, require_role, check_org_access
from app.db.session import get_db
from app.models import (
    SecurityControl,
    ControlMapping,
    FrameworkRequirement,
    Framework,
    User,
    UserRole,
    ImplementationStatus,
    TestingFrequency,
    MappingApprovalStatus,
    AuditEvent
)
from app.schemas.control import ControlCreate, ControlUpdate, ControlResponse, MappedRequirementSummary
from app.services.framework_comparison import get_framework_comparison_data

router = APIRouter(tags=["Frameworks & Controls"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


def format_control_response(control: SecurityControl) -> ControlResponse:
    """Helper to convert SecurityControl ORM entity to ControlResponse schema."""
    mapped_summaries = []
    for mapping in control.mappings:
        req = mapping.requirement
        fw = req.framework
        mapped_summaries.append(
            MappedRequirementSummary(
                id=mapping.id,
                framework_code=fw.code,
                framework_name=fw.name,
                identifier=req.identifier,
                title=req.title,
                category=req.category,
                approval_status=mapping.approval_status,
                mapping_rationale=mapping.mapping_rationale
            )
        )

    return ControlResponse(
        id=control.id,
        organization_id=control.organization_id,
        control_id=control.control_id,
        name=control.name,
        description=control.description,
        implementation_status=control.implementation_status,
        testing_frequency=control.testing_frequency,
        evidence_requirements=control.evidence_requirements,
        last_tested_at=control.last_tested_at,
        created_at=control.created_at,
        updated_at=control.updated_at,
        owner_id=control.owner_id,
        owner_name=control.owner.full_name if control.owner else None,
        owner_email=control.owner.email if control.owner else None,
        mapped_requirements=mapped_summaries
    )


# ==============================================================================
# Module A: Framework Comparison Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/frameworks/comparison")
async def api_framework_comparison():
    """
    Returns structured comparison matrix and domain specifications
    comparing SOC 2, ISO/IEC 27001:2022, and NIST CSF 2.0.
    """
    return get_framework_comparison_data()


@router.get(f"{settings.API_V1_STR}/frameworks/requirements")
async def api_framework_requirements(
    framework_code: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Lists framework requirements filtered optionally by framework code.
    """
    query = db.query(FrameworkRequirement).join(Framework)
    if framework_code:
        query = query.filter(Framework.code == framework_code.upper())
    reqs = query.order_by(Framework.code, FrameworkRequirement.identifier).all()
    return [
        {
            "id": r.id,
            "framework_code": r.framework.code,
            "identifier": r.identifier,
            "title": r.title,
            "category": r.category,
            "description": r.description,
            "guidance": r.guidance
        }
        for r in reqs
    ]


@router.get("/frameworks", response_class=HTMLResponse)
async def web_frameworks_comparison(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders interactive Framework Comparison View (Module A).
    """
    data = get_framework_comparison_data()
    frameworks = db.query(Framework).options(joinedload(Framework.requirements)).all()

    return templates.TemplateResponse(
        request=request,
        name="frameworks.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "comparison": data,
            "frameworks": frameworks,
            "title": "Framework Comparison: SOC 2 vs ISO 27001 vs NIST CSF 2.0"
        }
    )


# ==============================================================================
# Module B: Security Control Library REST API
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/controls", response_model=List[ControlResponse])
async def api_list_controls(
    status: Optional[ImplementationStatus] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves all security controls for the authenticated user's organization.
    Supports status filtering and text search.
    """
    org_id = current_user.organization_id or 1
    query = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id)

    if status:
        query = query.filter(SecurityControl.implementation_status == status)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (SecurityControl.control_id.ilike(s)) |
            (SecurityControl.name.ilike(s)) |
            (SecurityControl.description.ilike(s))
        )

    controls = query.order_by(SecurityControl.control_id).all()
    return [format_control_response(c) for c in controls]


@router.post(f"{settings.API_V1_STR}/controls", response_model=ControlResponse, status_code=status.HTTP_201_CREATED)
async def api_create_control(
    control_in: ControlCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST)),
    db: Session = Depends(get_db)
):
    """
    Creates a new internal security control within the organization.
    """
    org_id = current_user.organization_id or 1

    # Check for duplicate control_id in organization
    existing = db.query(SecurityControl).filter(
        SecurityControl.organization_id == org_id,
        SecurityControl.control_id == control_in.control_id.strip()
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Control with identifier '{control_in.control_id}' already exists in this organization."
        )

    new_control = SecurityControl(
        organization_id=org_id,
        control_id=control_in.control_id.strip().upper(),
        name=control_in.name.strip(),
        description=control_in.description.strip(),
        implementation_status=control_in.implementation_status,
        testing_frequency=control_in.testing_frequency,
        evidence_requirements=control_in.evidence_requirements.strip(),
        owner_id=control_in.owner_id or current_user.id
    )
    db.add(new_control)
    db.flush()

    # Log security audit trail event
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="CONTROL_CREATED",
        resource_type="SecurityControl",
        resource_id=new_control.id,
        details=f'{{"control_id": "{new_control.control_id}", "name": "{new_control.name}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_control)

    log_security_event(
        event_type="CONTROL_CREATED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Control:{new_control.control_id}"
    )

    return format_control_response(new_control)


@router.get(f"{settings.API_V1_STR}/controls/{{control_id}}", response_model=ControlResponse)
async def api_get_control(
    control_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves single control details and its mapped requirements.
    """
    org_id = current_user.organization_id or 1
    control = db.query(SecurityControl).filter(
        SecurityControl.organization_id == org_id,
        (SecurityControl.control_id == control_id) | (SecurityControl.id == (int(control_id) if control_id.isdigit() else -1))
    ).first()

    if not control:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")

    check_org_access(current_user, control.organization_id, request=request)
    return format_control_response(control)


@router.put(f"{settings.API_V1_STR}/controls/{{control_id}}", response_model=ControlResponse)
async def api_update_control(
    control_id: str,
    update_data: ControlUpdate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Updates an existing security control's status, description, or owner.
    """
    org_id = current_user.organization_id or 1
    control = db.query(SecurityControl).filter(
        SecurityControl.organization_id == org_id,
        (SecurityControl.control_id == control_id) | (SecurityControl.id == (int(control_id) if control_id.isdigit() else -1))
    ).first()

    if not control:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")

    check_org_access(current_user, control.organization_id, request=request)

    # Control owners may only edit controls they own
    if current_user.role == UserRole.CONTROL_OWNER and control.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Control owners may only update controls assigned to them."
        )

    if update_data.name is not None:
        control.name = update_data.name.strip()
    if update_data.description is not None:
        control.description = update_data.description.strip()
    if update_data.implementation_status is not None:
        control.implementation_status = update_data.implementation_status
    if update_data.testing_frequency is not None:
        control.testing_frequency = update_data.testing_frequency
    if update_data.evidence_requirements is not None:
        control.evidence_requirements = update_data.evidence_requirements.strip()
    if update_data.owner_id is not None:
        control.owner_id = update_data.owner_id

    control.updated_at = datetime.now(timezone.utc)

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="CONTROL_UPDATED",
        resource_type="SecurityControl",
        resource_id=control.id,
        details=f'{{"control_id": "{control.control_id}", "status": "{control.implementation_status.value}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(control)

    return format_control_response(control)


@router.delete(f"{settings.API_V1_STR}/controls/{{control_id}}", status_code=status.HTTP_204_NO_CONTENT)
async def api_delete_control(
    control_id: str,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Deletes a security control (Restricted to Administrators).
    """
    org_id = current_user.organization_id or 1
    control = db.query(SecurityControl).filter(
        SecurityControl.organization_id == org_id,
        (SecurityControl.control_id == control_id) | (SecurityControl.id == (int(control_id) if control_id.isdigit() else -1))
    ).first()

    if not control:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")

    cid = control.control_id
    db.delete(control)

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="CONTROL_DELETED",
        resource_type="SecurityControl",
        resource_id=control.id,
        details=f'{{"control_id": "{cid}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()

    log_security_event(
        event_type="CONTROL_DELETED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Control:{cid}",
        severity="WARNING"
    )
    return None


# ==============================================================================
# Module B: Web UI HTML Views
# ==============================================================================

@router.get("/controls", response_class=HTMLResponse)
async def web_controls_dashboard(
    request: Request,
    status_filter: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Centralized Security Control Library dashboard (Module B).
    """
    org_id = current_user.organization_id if current_user else 1
    query = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id)

    if status_filter and status_filter in [s.value for s in ImplementationStatus]:
        query = query.filter(SecurityControl.implementation_status == ImplementationStatus(status_filter))

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (SecurityControl.control_id.ilike(s)) |
            (SecurityControl.name.ilike(s)) |
            (SecurityControl.description.ilike(s))
        )

    controls = query.order_by(SecurityControl.control_id).all()
    all_users = db.query(User).filter(User.organization_id == org_id).all()

    # Calculate status counts for UI pills
    all_org_controls = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id).all()
    status_counts = {
        "ALL": len(all_org_controls),
        "IMPLEMENTED": sum(1 for c in all_org_controls if c.implementation_status == ImplementationStatus.IMPLEMENTED),
        "PARTIALLY_IMPLEMENTED": sum(1 for c in all_org_controls if c.implementation_status == ImplementationStatus.PARTIALLY_IMPLEMENTED),
        "NOT_IMPLEMENTED": sum(1 for c in all_org_controls if c.implementation_status == ImplementationStatus.NOT_IMPLEMENTED),
        "NEEDS_IMPROVEMENT": sum(1 for c in all_org_controls if c.implementation_status == ImplementationStatus.NEEDS_IMPROVEMENT),
    }

    return templates.TemplateResponse(
        request=request,
        name="controls.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "controls": controls,
            "users": all_users,
            "status_counts": status_counts,
            "active_status": status_filter,
            "search_query": search or "",
            "title": "Security Control Library | CyberGRC"
        }
    )


@router.post("/controls", response_class=RedirectResponse)
async def web_create_control_form(
    request: Request,
    control_id: str = Form(...),
    name: str = Form(...),
    description: str = Form(...),
    implementation_status: str = Form(...),
    testing_frequency: str = Form(...),
    evidence_requirements: str = Form(...),
    owner_id: Optional[int] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML modal form submission for creating a new control.
    """
    org_id = current_user.organization_id or 1
    new_control = SecurityControl(
        organization_id=org_id,
        control_id=control_id.strip().upper(),
        name=name.strip(),
        description=description.strip(),
        implementation_status=ImplementationStatus(implementation_status),
        testing_frequency=TestingFrequency(testing_frequency),
        evidence_requirements=evidence_requirements.strip(),
        owner_id=owner_id or current_user.id
    )
    db.add(new_control)
    db.flush()

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="CONTROL_CREATED",
        resource_type="SecurityControl",
        resource_id=new_control.id,
        details=f'{{"control_id": "{new_control.control_id}", "name": "{new_control.name}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()

    return RedirectResponse(url=f"/controls/{new_control.control_id}", status_code=status.HTTP_302_FOUND)


@router.get("/controls/{control_id}", response_class=HTMLResponse)
async def web_control_detail(
    control_id: str,
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders single Security Control Detail View showing cross-framework mappings,
    testing history, evidence checklist, and audit findings.
    """
    org_id = current_user.organization_id if current_user else 1
    control = db.query(SecurityControl).filter(
        SecurityControl.organization_id == org_id,
        SecurityControl.control_id == control_id
    ).first()

    if not control:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")

    all_users = db.query(User).filter(User.organization_id == org_id).all()

    return templates.TemplateResponse(
        request=request,
        name="control_detail.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "control": control,
            "users": all_users,
            "title": f"{control.control_id}: {control.name} | CyberGRC"
        }
    )


@router.post("/controls/{control_id}/edit", response_class=RedirectResponse)
async def web_edit_control_form(
    control_id: str,
    request: Request,
    name: str = Form(...),
    description: str = Form(...),
    implementation_status: str = Form(...),
    testing_frequency: str = Form(...),
    evidence_requirements: str = Form(...),
    owner_id: Optional[int] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML edit form submission for updating a control.
    """
    org_id = current_user.organization_id or 1
    control = db.query(SecurityControl).filter(
        SecurityControl.organization_id == org_id,
        SecurityControl.control_id == control_id
    ).first()

    if not control:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")

    if current_user.role == UserRole.CONTROL_OWNER and control.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")

    control.name = name.strip()
    control.description = description.strip()
    control.implementation_status = ImplementationStatus(implementation_status)
    control.testing_frequency = TestingFrequency(testing_frequency)
    control.evidence_requirements = evidence_requirements.strip()
    if owner_id:
        control.owner_id = owner_id
    control.updated_at = datetime.now(timezone.utc)

    db.commit()
    return RedirectResponse(url=f"/controls/{control.control_id}", status_code=status.HTTP_302_FOUND)
