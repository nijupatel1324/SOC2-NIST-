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
    RiskAssessment,
    SecurityControl,
    User,
    UserRole,
    RiskLevel,
    RiskTreatmentStrategy,
    RiskStatus,
    AuditEvent
)
from app.schemas.risk import (
    RiskCreate,
    RiskUpdate,
    RiskAcceptanceRequest,
    RiskResponse,
    RiskMatrixSummary
)
from app.services.risk_service import (
    compute_risk_score_and_level,
    get_risk_matrix_summary,
    format_risk_response
)

router = APIRouter(tags=["Risk Register & Treatment"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


# ==============================================================================
# Module D: REST API Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/risks", response_model=List[RiskResponse])
async def api_list_risks(
    level: Optional[RiskLevel] = None,
    status_filter: Optional[RiskStatus] = None,
    strategy: Optional[RiskTreatmentStrategy] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists enterprise cybersecurity risks for the authenticated organization.
    Supports filtering by inherent risk level, lifecycle status, treatment strategy, and search.
    """
    org_id = current_user.organization_id or 1
    query = db.query(RiskAssessment).filter(RiskAssessment.organization_id == org_id).options(
        joinedload(RiskAssessment.owner),
        joinedload(RiskAssessment.risk_accepted_by)
    )

    if level:
        query = query.filter(RiskAssessment.inherent_level == level)

    if status_filter:
        query = query.filter(RiskAssessment.status == status_filter)

    if strategy:
        query = query.filter(RiskAssessment.treatment_strategy == strategy)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (RiskAssessment.risk_id.ilike(s)) |
            (RiskAssessment.title.ilike(s)) |
            (RiskAssessment.affected_asset.ilike(s)) |
            (RiskAssessment.threat_source.ilike(s))
        )

    risks = query.order_by(RiskAssessment.inherent_score.desc()).all()
    return [format_risk_response(r) for r in risks]


@router.get(f"{settings.API_V1_STR}/risks/matrix", response_model=RiskMatrixSummary)
async def api_risk_matrix(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns 5x5 Likelihood x Impact Heatmap Matrix distribution data
    comparing Inherent vs Residual risk exposure.
    """
    org_id = current_user.organization_id or 1
    return get_risk_matrix_summary(db, org_id)


@router.post(f"{settings.API_V1_STR}/risks", response_model=RiskResponse, status_code=status.HTTP_201_CREATED)
async def api_create_risk(
    risk_in: RiskCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Creates a new risk assessment with automatic inherent and residual score calculations.
    """
    org_id = current_user.organization_id or 1

    # Check for duplicate risk identifier
    existing = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id,
        RiskAssessment.risk_id == risk_in.risk_id.strip().upper()
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Risk with identifier '{risk_in.risk_id}' already exists in this organization."
        )

    inh_score, inh_level = compute_risk_score_and_level(risk_in.inherent_likelihood, risk_in.inherent_impact)
    res_score, res_level = compute_risk_score_and_level(risk_in.residual_likelihood, risk_in.residual_impact)

    new_risk = RiskAssessment(
        organization_id=org_id,
        risk_id=risk_in.risk_id.strip().upper(),
        title=risk_in.title.strip(),
        affected_asset=risk_in.affected_asset.strip(),
        threat_source=risk_in.threat_source.strip(),
        vulnerability=risk_in.vulnerability.strip(),
        business_impact=risk_in.business_impact.strip(),
        owner_id=risk_in.owner_id or current_user.id,
        inherent_likelihood=risk_in.inherent_likelihood,
        inherent_impact=risk_in.inherent_impact,
        inherent_score=inh_score,
        inherent_level=inh_level,
        existing_safeguards=risk_in.existing_safeguards.strip() if risk_in.existing_safeguards else None,
        residual_likelihood=risk_in.residual_likelihood,
        residual_impact=risk_in.residual_impact,
        residual_score=res_score,
        residual_level=res_level,
        treatment_strategy=risk_in.treatment_strategy,
        treatment_details=risk_in.treatment_details.strip(),
        status=risk_in.status
    )

    if risk_in.treatment_strategy == RiskTreatmentStrategy.ACCEPT and risk_in.risk_acceptance_rationale:
        new_risk.risk_acceptance_rationale = risk_in.risk_acceptance_rationale.strip()
        new_risk.risk_accepted_by_id = current_user.id
        new_risk.risk_accepted_at = datetime.now(timezone.utc)
        new_risk.status = RiskStatus.ACCEPTED

    db.add(new_risk)
    db.flush()

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="RISK_CREATED",
        resource_type="RiskAssessment",
        resource_id=new_risk.id,
        details=f'{{"risk_id": "{new_risk.risk_id}", "inherent_score": {inh_score}, "residual_score": {res_score}}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_risk)

    log_security_event(
        event_type="RISK_CREATED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Risk:{new_risk.risk_id}"
    )

    return format_risk_response(new_risk)


@router.get(f"{settings.API_V1_STR}/risks/{{risk_id}}", response_model=RiskResponse)
async def api_get_risk(
    risk_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves full risk details by risk_id string or database integer ID.
    """
    org_id = current_user.organization_id or 1
    risk = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id,
        (RiskAssessment.risk_id == risk_id.strip().upper()) | (RiskAssessment.id == (int(risk_id) if risk_id.isdigit() else -1))
    ).options(
        joinedload(RiskAssessment.owner),
        joinedload(RiskAssessment.risk_accepted_by)
    ).first()

    if not risk:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk assessment not found.")

    check_org_access(current_user, risk.organization_id, request=request)
    return format_risk_response(risk)


@router.put(f"{settings.API_V1_STR}/risks/{{risk_id}}", response_model=RiskResponse)
async def api_update_risk(
    risk_id: str,
    update_in: RiskUpdate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Updates risk ratings, treatment strategy, or safeguards.
    Automatically recalculates risk score and level if ratings change.
    """
    org_id = current_user.organization_id or 1
    risk = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id,
        (RiskAssessment.risk_id == risk_id.strip().upper()) | (RiskAssessment.id == (int(risk_id) if risk_id.isdigit() else -1))
    ).first()

    if not risk:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk assessment not found.")

    check_org_access(current_user, risk.organization_id, request=request)

    if update_in.title is not None:
        risk.title = update_in.title.strip()
    if update_in.affected_asset is not None:
        risk.affected_asset = update_in.affected_asset.strip()
    if update_in.threat_source is not None:
        risk.threat_source = update_in.threat_source.strip()
    if update_in.vulnerability is not None:
        risk.vulnerability = update_in.vulnerability.strip()
    if update_in.business_impact is not None:
        risk.business_impact = update_in.business_impact.strip()
    if update_in.owner_id is not None:
        risk.owner_id = update_in.owner_id
    if update_in.existing_safeguards is not None:
        risk.existing_safeguards = update_in.existing_safeguards.strip()
    if update_in.treatment_strategy is not None:
        risk.treatment_strategy = update_in.treatment_strategy
    if update_in.treatment_details is not None:
        risk.treatment_details = update_in.treatment_details.strip()
    if update_in.status is not None:
        risk.status = update_in.status

    # Recalculate inherent risk if L or I updated
    if update_in.inherent_likelihood is not None:
        risk.inherent_likelihood = update_in.inherent_likelihood
    if update_in.inherent_impact is not None:
        risk.inherent_impact = update_in.inherent_impact
    risk.inherent_score, risk.inherent_level = compute_risk_score_and_level(risk.inherent_likelihood, risk.inherent_impact)

    # Recalculate residual risk if L or I updated
    if update_in.residual_likelihood is not None:
        risk.residual_likelihood = update_in.residual_likelihood
    if update_in.residual_impact is not None:
        risk.residual_impact = update_in.residual_impact
    risk.residual_score, risk.residual_level = compute_risk_score_and_level(risk.residual_likelihood, risk.residual_impact)

    risk.updated_at = datetime.now(timezone.utc)

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="RISK_UPDATED",
        resource_type="RiskAssessment",
        resource_id=risk.id,
        details=f'{{"inherent_score": {risk.inherent_score}, "residual_score": {risk.residual_score}, "status": "{risk.status.value}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(risk)

    return format_risk_response(risk)


@router.post(f"{settings.API_V1_STR}/risks/{{risk_id}}/accept", response_model=RiskResponse)
async def api_accept_risk(
    risk_id: str,
    accept_in: RiskAcceptanceRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Formal executive risk acceptance sign-off workflow.
    Requires business justification and records executive authorization timestamp.
    """
    org_id = current_user.organization_id or 1
    risk = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id,
        (RiskAssessment.risk_id == risk_id.strip().upper()) | (RiskAssessment.id == (int(risk_id) if risk_id.isdigit() else -1))
    ).first()

    if not risk:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk assessment not found.")

    risk.treatment_strategy = RiskTreatmentStrategy.ACCEPT
    risk.status = RiskStatus.ACCEPTED
    risk.risk_acceptance_rationale = accept_in.rationale.strip()
    risk.risk_accepted_by_id = current_user.id
    risk.risk_accepted_at = datetime.now(timezone.utc)
    risk.updated_at = datetime.now(timezone.utc)

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="RISK_ACCEPTED",
        resource_type="RiskAssessment",
        resource_id=risk.id,
        details=f'{{"risk_id": "{risk.risk_id}", "accepted_by": "{current_user.email}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(risk)

    log_security_event(
        event_type="RISK_ACCEPTED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Risk:{risk.risk_id}",
        severity="WARNING"
    )

    return format_risk_response(risk)


@router.delete(f"{settings.API_V1_STR}/risks/{{risk_id}}", status_code=status.HTTP_204_NO_CONTENT)
async def api_delete_risk(
    risk_id: str,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Deletes a risk assessment from the register (restricted to Administrators).
    """
    org_id = current_user.organization_id or 1
    risk = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id,
        (RiskAssessment.risk_id == risk_id.strip().upper()) | (RiskAssessment.id == (int(risk_id) if risk_id.isdigit() else -1))
    ).first()

    if not risk:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk assessment not found.")

    rid = risk.risk_id
    db.delete(risk)

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="RISK_DELETED",
        resource_type="RiskAssessment",
        resource_id=risk.id,
        details=f'{{"risk_id": "{rid}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()

    log_security_event(
        event_type="RISK_DELETED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Risk:{rid}",
        severity="WARNING"
    )
    return None


# ==============================================================================
# Module D: Web UI HTML Views
# ==============================================================================

@router.get("/risks", response_class=HTMLResponse)
async def web_risk_register(
    request: Request,
    level: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
    heatmap_view: str = Query("inherent"),  # "inherent" or "residual"
    search: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Risk Register Dashboard with interactive 5x5 Heatmap Matrix (Module D).
    """
    org_id = current_user.organization_id if current_user else 1

    # Get 5x5 matrix summary
    matrix_summary = get_risk_matrix_summary(db, org_id)

    # Filtered risk list query
    query = db.query(RiskAssessment).filter(RiskAssessment.organization_id == org_id).options(
        joinedload(RiskAssessment.owner),
        joinedload(RiskAssessment.risk_accepted_by)
    )

    if level and level in [l.value for l in RiskLevel]:
        query = query.filter(RiskAssessment.inherent_level == RiskLevel(level))

    if status_filter and status_filter in [s.value for s in RiskStatus]:
        query = query.filter(RiskAssessment.status == RiskStatus(status_filter))

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (RiskAssessment.risk_id.ilike(s)) |
            (RiskAssessment.title.ilike(s)) |
            (RiskAssessment.affected_asset.ilike(s))
        )

    risks = query.order_by(RiskAssessment.inherent_score.desc()).all()
    all_users = db.query(User).filter(User.organization_id == org_id).all()

    # Calculate status counts
    all_org_risks = db.query(RiskAssessment).filter(RiskAssessment.organization_id == org_id).all()
    level_counts = {
        "ALL": len(all_org_risks),
        "CRITICAL": sum(1 for r in all_org_risks if r.inherent_level == RiskLevel.CRITICAL),
        "HIGH": sum(1 for r in all_org_risks if r.inherent_level == RiskLevel.HIGH),
        "MEDIUM": sum(1 for r in all_org_risks if r.inherent_level == RiskLevel.MEDIUM),
        "LOW": sum(1 for r in all_org_risks if r.inherent_level == RiskLevel.LOW),
    }

    return templates.TemplateResponse(
        request=request,
        name="risks.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "matrix_summary": matrix_summary,
            "risks": risks,
            "users": all_users,
            "level_counts": level_counts,
            "active_level": level or "ALL",
            "active_status": status_filter or "ALL",
            "heatmap_view": heatmap_view,
            "search_query": search or "",
            "title": "Enterprise Risk Register & 5x5 Heatmap | CyberGRC"
        }
    )


@router.post("/risks", response_class=RedirectResponse)
async def web_create_risk_form(
    request: Request,
    risk_id: str = Form(...),
    title: str = Form(...),
    affected_asset: str = Form(...),
    threat_source: str = Form(...),
    vulnerability: str = Form(...),
    business_impact: str = Form(...),
    inherent_likelihood: int = Form(...),
    inherent_impact: int = Form(...),
    residual_likelihood: int = Form(...),
    residual_impact: int = Form(...),
    treatment_strategy: str = Form(...),
    treatment_details: str = Form(...),
    existing_safeguards: Optional[str] = Form(None),
    owner_id: Optional[int] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML modal form submission for creating a new risk assessment.
    """
    org_id = current_user.organization_id or 1

    inh_score, inh_level = compute_risk_score_and_level(inherent_likelihood, inherent_impact)
    res_score, res_level = compute_risk_score_and_level(residual_likelihood, residual_impact)

    new_risk = RiskAssessment(
        organization_id=org_id,
        risk_id=risk_id.strip().upper(),
        title=title.strip(),
        affected_asset=affected_asset.strip(),
        threat_source=threat_source.strip(),
        vulnerability=vulnerability.strip(),
        business_impact=business_impact.strip(),
        owner_id=owner_id or current_user.id,
        inherent_likelihood=inherent_likelihood,
        inherent_impact=inherent_impact,
        inherent_score=inh_score,
        inherent_level=inh_level,
        existing_safeguards=existing_safeguards.strip() if existing_safeguards else None,
        residual_likelihood=residual_likelihood,
        residual_impact=residual_impact,
        residual_score=res_score,
        residual_level=res_level,
        treatment_strategy=RiskTreatmentStrategy(treatment_strategy),
        treatment_details=treatment_details.strip(),
        status=RiskStatus.IDENTIFIED
    )
    db.add(new_risk)
    db.flush()

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="RISK_CREATED",
        resource_type="RiskAssessment",
        resource_id=new_risk.id,
        details=f'{{"risk_id": "{new_risk.risk_id}", "inherent_score": {inh_score}, "residual_score": {res_score}}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()

    return RedirectResponse(url="/risks", status_code=status.HTTP_302_FOUND)


@router.get("/risks/{risk_id}", response_class=HTMLResponse)
async def web_risk_detail(
    risk_id: str,
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders detailed view for a single risk assessment with treatment action plan.
    """
    org_id = current_user.organization_id if current_user else 1
    risk = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id,
        (RiskAssessment.risk_id == risk_id.strip().upper()) | (RiskAssessment.id == (int(risk_id) if risk_id.isdigit() else -1))
    ).options(
        joinedload(RiskAssessment.owner),
        joinedload(RiskAssessment.risk_accepted_by)
    ).first()

    if not risk:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk not found.")

    all_users = db.query(User).filter(User.organization_id == org_id).all()

    return templates.TemplateResponse(
        request=request,
        name="risk_detail.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "risk": risk,
            "users": all_users,
            "title": f"{risk.risk_id}: {risk.title} | CyberGRC"
        }
    )


@router.post("/risks/{risk_id}/accept", response_class=RedirectResponse)
async def web_accept_risk_form(
    risk_id: str,
    request: Request,
    rationale: str = Form(...),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML modal form submission for formal executive risk acceptance.
    """
    org_id = current_user.organization_id or 1
    risk = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id,
        (RiskAssessment.risk_id == risk_id.strip().upper()) | (RiskAssessment.id == (int(risk_id) if risk_id.isdigit() else -1))
    ).first()

    if risk:
        risk.treatment_strategy = RiskTreatmentStrategy.ACCEPT
        risk.status = RiskStatus.ACCEPTED
        risk.risk_acceptance_rationale = rationale.strip()
        risk.risk_accepted_by_id = current_user.id
        risk.risk_accepted_at = datetime.now(timezone.utc)
        risk.updated_at = datetime.now(timezone.utc)

        audit_evt = AuditEvent(
            organization_id=org_id,
            user_id=current_user.id,
            action="RISK_ACCEPTED",
            resource_type="RiskAssessment",
            resource_id=risk.id,
            details=f'{{"risk_id": "{risk.risk_id}", "accepted_by": "{current_user.email}"}}',
            ip_address=request.client.host if request.client else "unknown"
        )
        db.add(audit_evt)
        db.commit()

    return RedirectResponse(url=f"/risks/{risk.risk_id}", status_code=status.HTTP_302_FOUND)
