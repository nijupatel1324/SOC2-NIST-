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
    ComplianceAssessment,
    FrameworkRequirement,
    Framework,
    SecurityControl,
    ControlMapping,
    User,
    UserRole,
    AssessmentStatus,
    AuditEvent
)
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentUpdate,
    AssessmentResponse,
    AssessmentFrameworkSummary
)
from app.services.assessment_service import (
    get_framework_readiness_summaries,
    format_assessment_response
)

router = APIRouter(tags=["Compliance Gap Assessments"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


# ==============================================================================
# Module E: REST API Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/assessments/summary", response_model=List[AssessmentFrameworkSummary])
async def api_assessments_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns framework-by-framework compliance readiness calculations.
    Specifies explicit formulas, applicable denominators, and non-certification boundaries.
    """
    org_id = current_user.organization_id or 1
    return get_framework_readiness_summaries(db, org_id)


@router.get(f"{settings.API_V1_STR}/assessments", response_model=List[AssessmentResponse])
async def api_list_assessments(
    framework_code: Optional[str] = None,
    status_filter: Optional[AssessmentStatus] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists compliance assessments for the authenticated organization.
    Includes requirement metadata, category, and mapped control counts.
    """
    org_id = current_user.organization_id or 1

    # Base requirements query with optional framework filter
    req_query = db.query(FrameworkRequirement).join(Framework).options(
        joinedload(FrameworkRequirement.framework),
        joinedload(FrameworkRequirement.mappings).joinedload(ControlMapping.control),
        joinedload(FrameworkRequirement.assessments)
    )

    if framework_code:
        req_query = req_query.filter(Framework.code == framework_code.strip().upper())

    requirements = req_query.order_by(Framework.code, FrameworkRequirement.identifier).all()
    results = []

    for req in requirements:
        # Find existing assessment for org
        assessment = next((a for a in req.assessments if a.organization_id == org_id), None)
        if not assessment:
            # Create synthetic default NOT_ASSESSED object for schema representation
            assessment = ComplianceAssessment(
                id=0,
                organization_id=org_id,
                requirement_id=req.id,
                status=AssessmentStatus.NOT_ASSESSED,
                justification=None,
                assessed_by_id=None,
                identified_gaps=None,
                recommended_actions=None,
                assessed_at=None,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

        if status_filter and assessment.status != status_filter:
            continue

        results.append(format_assessment_response(assessment, req))

    return results


@router.get(f"{settings.API_V1_STR}/assessments/{{requirement_id}}", response_model=AssessmentResponse)
async def api_get_requirement_assessment(
    requirement_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves the compliance assessment for a specific framework requirement.
    """
    org_id = current_user.organization_id or 1
    req = db.query(FrameworkRequirement).filter(
        FrameworkRequirement.id == requirement_id
    ).options(
        joinedload(FrameworkRequirement.framework),
        joinedload(FrameworkRequirement.mappings).joinedload(ControlMapping.control),
        joinedload(FrameworkRequirement.assessments)
    ).first()

    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Framework requirement not found.")

    assessment = next((a for a in req.assessments if a.organization_id == org_id), None)
    if not assessment:
        assessment = ComplianceAssessment(
            id=0,
            organization_id=org_id,
            requirement_id=req.id,
            status=AssessmentStatus.NOT_ASSESSED,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

    return format_assessment_response(assessment, req)


@router.post(f"{settings.API_V1_STR}/assessments", response_model=AssessmentResponse, status_code=status.HTTP_200_OK)
async def api_upsert_assessment(
    assessment_in: AssessmentCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Creates or updates the compliance assessment for a requirement (upsert).
    Enforces mandatory justification when status is NOT_APPLICABLE.
    """
    org_id = current_user.organization_id or 1

    req = db.query(FrameworkRequirement).filter(
        FrameworkRequirement.id == assessment_in.requirement_id
    ).options(
        joinedload(FrameworkRequirement.framework),
        joinedload(FrameworkRequirement.mappings).joinedload(ControlMapping.control)
    ).first()

    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Framework requirement with ID {assessment_in.requirement_id} does not exist."
        )

    # Validate mandatory justification for NOT_APPLICABLE
    if assessment_in.status == AssessmentStatus.NOT_APPLICABLE:
        if not assessment_in.justification or not assessment_in.justification.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A documented justification is mandatory when marking a requirement as NOT_APPLICABLE."
            )

    assessment = db.query(ComplianceAssessment).filter(
        ComplianceAssessment.organization_id == org_id,
        ComplianceAssessment.requirement_id == assessment_in.requirement_id
    ).first()

    is_new = False
    if not assessment:
        is_new = True
        assessment = ComplianceAssessment(
            organization_id=org_id,
            requirement_id=assessment_in.requirement_id
        )
        db.add(assessment)

    assessment.status = assessment_in.status
    assessment.justification = assessment_in.justification.strip() if assessment_in.justification else None
    assessment.identified_gaps = assessment_in.identified_gaps.strip() if assessment_in.identified_gaps else None
    assessment.recommended_actions = assessment_in.recommended_actions.strip() if assessment_in.recommended_actions else None
    assessment.assessed_by_id = current_user.id
    assessment.assessed_at = datetime.now(timezone.utc)
    assessment.updated_at = datetime.now(timezone.utc)

    db.flush()

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="ASSESSMENT_CREATED" if is_new else "ASSESSMENT_UPDATED",
        resource_type="ComplianceAssessment",
        resource_id=assessment.id,
        details=(
            f'{{"requirement": "{req.identifier}", "framework": "{req.framework.code}", '
            f'"status": "{assessment.status.value}"}}'
        ),
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(assessment)

    log_security_event(
        event_type="ASSESSMENT_UPDATED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Assessment:{req.identifier}->{assessment.status.value}"
    )

    return format_assessment_response(assessment, req)


# ==============================================================================
# Module E: Web UI HTML Views
# ==============================================================================

@router.get("/assessments", response_class=HTMLResponse)
async def web_assessments_dashboard(
    request: Request,
    framework: Optional[str] = Query("SOC2"),
    status_filter: Optional[str] = Query("ALL"),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Compliance Gap Assessment & Readiness Matrix dashboard (Module E).
    Displays framework readiness scores, 6-state status breakdown, and interactive assessment modal.
    """
    org_id = current_user.organization_id if current_user else 1

    # Get framework summaries
    summaries = get_framework_readiness_summaries(db, org_id)

    # Active framework code
    selected_fw_code = (framework or "SOC2").upper()
    active_summary = next((s for s in summaries if s.framework_code == selected_fw_code), summaries[0] if summaries else None)

    # Query requirements for selected framework
    req_query = db.query(FrameworkRequirement).join(Framework).filter(
        Framework.code == selected_fw_code
    ).options(
        joinedload(FrameworkRequirement.framework),
        joinedload(FrameworkRequirement.mappings).joinedload(ControlMapping.control),
        joinedload(FrameworkRequirement.assessments)
    ).order_by(FrameworkRequirement.identifier)

    requirements = req_query.all()

    # Build structured view items with assessment status & gaps
    items = []
    status_counts = {
        "ALL": len(requirements),
        "GAPS_ONLY": 0,
        "IMPLEMENTED": 0,
        "PARTIALLY_IMPLEMENTED": 0,
        "NEEDS_IMPROVEMENT": 0,
        "NOT_IMPLEMENTED": 0,
        "NOT_ASSESSED": 0,
        "NOT_APPLICABLE": 0,
    }

    for req in requirements:
        ass = next((a for a in req.assessments if a.organization_id == org_id), None)
        curr_status = ass.status if ass else AssessmentStatus.NOT_ASSESSED

        # Update count tallies
        status_counts[curr_status.value] = status_counts.get(curr_status.value, 0) + 1
        if curr_status in [AssessmentStatus.NOT_IMPLEMENTED, AssessmentStatus.PARTIALLY_IMPLEMENTED, AssessmentStatus.NEEDS_IMPROVEMENT]:
            status_counts["GAPS_ONLY"] += 1

        # Check filter
        if status_filter == "GAPS_ONLY":
            if curr_status not in [AssessmentStatus.NOT_IMPLEMENTED, AssessmentStatus.PARTIALLY_IMPLEMENTED, AssessmentStatus.NEEDS_IMPROVEMENT]:
                continue
        elif status_filter and status_filter != "ALL":
            if curr_status.value != status_filter:
                continue

        items.append({
            "requirement": req,
            "assessment": ass,
            "status": curr_status,
            "mapped_controls": [m.control for m in req.mappings],
        })

    return templates.TemplateResponse(
        request=request,
        name="assessments.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "summaries": summaries,
            "active_summary": active_summary,
            "selected_framework": selected_fw_code,
            "status_filter": status_filter or "ALL",
            "status_counts": status_counts,
            "items": items,
            "title": f"{selected_fw_code} Compliance Gap Assessment | CyberGRC"
        }
    )


@router.post("/assessments", response_class=RedirectResponse)
async def web_record_assessment_form(
    request: Request,
    requirement_id: int = Form(...),
    framework_code: str = Form("SOC2"),
    assessment_status: str = Form(...),
    justification: Optional[str] = Form(None),
    identified_gaps: Optional[str] = Form(None),
    recommended_actions: Optional[str] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML modal form submission for recording/updating an assessment.
    """
    org_id = current_user.organization_id or 1
    target_status = AssessmentStatus(assessment_status)

    if target_status == AssessmentStatus.NOT_APPLICABLE and (not justification or not justification.strip()):
        # Handle invalid input gracefully by redirecting
        return RedirectResponse(
            url=f"/assessments?framework={framework_code}&error=justification_required",
            status_code=status.HTTP_302_FOUND
        )

    assessment = db.query(ComplianceAssessment).filter(
        ComplianceAssessment.organization_id == org_id,
        ComplianceAssessment.requirement_id == requirement_id
    ).first()

    if not assessment:
        assessment = ComplianceAssessment(
            organization_id=org_id,
            requirement_id=requirement_id
        )
        db.add(assessment)

    assessment.status = target_status
    assessment.justification = justification.strip() if justification else None
    assessment.identified_gaps = identified_gaps.strip() if identified_gaps else None
    assessment.recommended_actions = recommended_actions.strip() if recommended_actions else None
    assessment.assessed_by_id = current_user.id
    assessment.assessed_at = datetime.now(timezone.utc)
    assessment.updated_at = datetime.now(timezone.utc)

    db.commit()

    return RedirectResponse(
        url=f"/assessments?framework={framework_code}",
        status_code=status.HTTP_302_FOUND
    )
