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
    AuditFinding,
    CorrectiveAction,
    SecurityControl,
    ControlTest,
    User,
    UserRole,
    FindingSeverity,
    FindingStatus,
    ActionStatus,
    AuditEvent
)
from app.schemas.finding import (
    FindingCreate,
    FindingUpdate,
    FindingCloseRequest,
    FindingResponse,
    FindingDetailResponse,
    CorrectiveActionCreate,
    CorrectiveActionUpdate,
    CorrectiveActionResponse
)
from app.services.finding_service import (
    format_finding_response,
    format_finding_detail_response,
    format_action_response
)

router = APIRouter(tags=["Audit Findings & CAPA Remediation"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


# ==============================================================================
# Module G & H: REST API Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/findings", response_model=List[FindingResponse])
async def api_list_findings(
    status: Optional[FindingStatus] = None,
    severity: Optional[FindingSeverity] = None,
    control_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists audit findings and deficiencies for the user's organization.
    Supports filtering by status, severity, and target security control.
    """
    org_id = current_user.organization_id or 1
    query = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id
    ).options(
        joinedload(AuditFinding.control),
        joinedload(AuditFinding.control_test),
        joinedload(AuditFinding.owner),
        joinedload(AuditFinding.closed_by),
        joinedload(AuditFinding.corrective_actions)
    )

    if status:
        query = query.filter(AuditFinding.status == status)

    if severity:
        query = query.filter(AuditFinding.severity == severity)

    if control_id:
        query = query.filter(AuditFinding.control_id == control_id)

    findings = query.order_by(AuditFinding.created_at.desc()).all()
    return [format_finding_response(f) for f in findings]


@router.post(f"{settings.API_V1_STR}/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
async def api_create_finding(
    finding_in: FindingCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Documents a new audit finding or compliance deficiency.
    Binds to a target security control and optionally to a failed control test.
    """
    org_id = current_user.organization_id or 1

    ctrl = db.query(SecurityControl).filter(
        SecurityControl.id == finding_in.control_id,
        SecurityControl.organization_id == org_id
    ).first()
    if not ctrl:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target security control not found.")

    # Check for unique finding_id in org
    existing = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        AuditFinding.finding_id == finding_in.finding_id.strip()
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Finding identifier '{finding_in.finding_id}' already exists in your organization."
        )

    if finding_in.control_test_id:
        test = db.query(ControlTest).filter(
            ControlTest.id == finding_in.control_test_id,
            ControlTest.organization_id == org_id
        ).first()
        if not test:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked control test not found.")

    new_finding = AuditFinding(
        organization_id=org_id,
        finding_id=finding_in.finding_id.strip(),
        control_id=finding_in.control_id,
        control_test_id=finding_in.control_test_id,
        title=finding_in.title.strip(),
        severity=finding_in.severity,
        root_cause=finding_in.root_cause.strip(),
        business_impact=finding_in.business_impact.strip(),
        owner_id=finding_in.owner_id or current_user.id,
        due_date=finding_in.due_date,
        status=FindingStatus.OPEN
    )
    db.add(new_finding)
    db.flush()

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="FINDING_LOGGED",
        resource_type="AuditFinding",
        resource_id=new_finding.id,
        details=f'{{"finding_id": "{new_finding.finding_id}", "severity": "{new_finding.severity.value}", "control_id": "{ctrl.control_id}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_finding)

    log_security_event(
        event_type="FINDING_CREATED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Finding:{new_finding.finding_id}->{new_finding.severity.value}"
    )

    return format_finding_response(new_finding)


@router.get(f"{settings.API_V1_STR}/findings/{{finding_identifier}}", response_model=FindingDetailResponse)
async def api_get_finding(
    finding_identifier: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves complete details of an audit finding including root cause,
    business impact, and all corrective action plans (CAPA).
    """
    org_id = current_user.organization_id or 1
    finding = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        (AuditFinding.finding_id == finding_identifier) | (AuditFinding.id == (int(finding_identifier) if finding_identifier.isdigit() else -1))
    ).options(
        joinedload(AuditFinding.control),
        joinedload(AuditFinding.control_test),
        joinedload(AuditFinding.owner),
        joinedload(AuditFinding.closed_by),
        joinedload(AuditFinding.corrective_actions).joinedload(CorrectiveAction.owner)
    ).first()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit finding not found.")

    check_org_access(current_user, finding.organization_id, request=request)
    return format_finding_detail_response(finding)


@router.patch(f"{settings.API_V1_STR}/findings/{{finding_identifier}}", response_model=FindingResponse)
async def api_update_finding(
    finding_identifier: str,
    update_in: FindingUpdate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Updates finding metadata, severity, due date, owner, or status.
    """
    org_id = current_user.organization_id or 1
    finding = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        (AuditFinding.finding_id == finding_identifier) | (AuditFinding.id == (int(finding_identifier) if finding_identifier.isdigit() else -1))
    ).first()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit finding not found.")

    check_org_access(current_user, finding.organization_id, request=request)

    if update_in.title is not None:
        finding.title = update_in.title.strip()
    if update_in.severity is not None:
        finding.severity = update_in.severity
    if update_in.root_cause is not None:
        finding.root_cause = update_in.root_cause.strip()
    if update_in.business_impact is not None:
        finding.business_impact = update_in.business_impact.strip()
    if update_in.owner_id is not None:
        finding.owner_id = update_in.owner_id
    if update_in.due_date is not None:
        finding.due_date = update_in.due_date
    if update_in.status is not None:
        finding.status = update_in.status

    db.commit()
    db.refresh(finding)

    return format_finding_response(finding)


@router.post(f"{settings.API_V1_STR}/findings/{{finding_identifier}}/actions", response_model=CorrectiveActionResponse, status_code=status.HTTP_201_CREATED)
async def api_create_corrective_action(
    finding_identifier: str,
    action_in: CorrectiveActionCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Creates a new Corrective Action Plan (CAPA) item tied to the finding.
    Automatically transitions finding status to REMEDIATION_IN_PROGRESS if OPEN.
    """
    org_id = current_user.organization_id or 1
    finding = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        (AuditFinding.finding_id == finding_identifier) | (AuditFinding.id == (int(finding_identifier) if finding_identifier.isdigit() else -1))
    ).first()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit finding not found.")

    check_org_access(current_user, finding.organization_id, request=request)

    new_action = CorrectiveAction(
        organization_id=org_id,
        finding_id=finding.id,
        action_plan=action_in.action_plan.strip(),
        owner_id=action_in.owner_id or current_user.id,
        target_completion_date=action_in.target_completion_date,
        status=ActionStatus.OPEN,
        notes=action_in.notes.strip() if action_in.notes else None
    )
    db.add(new_action)

    # Transition finding to REMEDIATION_IN_PROGRESS if still OPEN
    if finding.status == FindingStatus.OPEN:
        finding.status = FindingStatus.REMEDIATION_IN_PROGRESS

    db.flush()

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="CAPA_CREATED",
        resource_type="CorrectiveAction",
        resource_id=new_action.id,
        details=f'{{"finding_id": "{finding.finding_id}", "action_id": {new_action.id}}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_action)

    return format_action_response(new_action)


@router.patch(f"{settings.API_V1_STR}/findings/{{finding_identifier}}/actions/{{action_id}}", response_model=CorrectiveActionResponse)
async def api_update_corrective_action(
    finding_identifier: str,
    action_id: int,
    action_in: CorrectiveActionUpdate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Updates corrective action plan progress (e.g. IN_PROGRESS, IMPLEMENTED, VERIFIED).
    """
    org_id = current_user.organization_id or 1
    action = db.query(CorrectiveAction).filter(
        CorrectiveAction.id == action_id,
        CorrectiveAction.organization_id == org_id
    ).first()

    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Corrective action not found.")

    if action_in.action_plan is not None:
        action.action_plan = action_in.action_plan.strip()
    if action_in.owner_id is not None:
        action.owner_id = action_in.owner_id
    if action_in.target_completion_date is not None:
        action.target_completion_date = action_in.target_completion_date
    if action_in.actual_completion_date is not None:
        action.actual_completion_date = action_in.actual_completion_date
    if action_in.status is not None:
        action.status = action_in.status
        if action_in.status in [ActionStatus.IMPLEMENTED, ActionStatus.VERIFIED] and not action.actual_completion_date:
            action.actual_completion_date = datetime.now(timezone.utc)
    if action_in.notes is not None:
        action.notes = action_in.notes.strip()

    db.commit()
    db.refresh(action)

    return format_action_response(action)


@router.post(f"{settings.API_V1_STR}/findings/{{finding_identifier}}/close", response_model=FindingResponse)
async def api_close_finding(
    finding_identifier: str,
    close_in: FindingCloseRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Formal Auditor / CISO verification and sign-off to close a finding.
    Requires justification rationale and sets closed_at timestamp.
    """
    org_id = current_user.organization_id or 1
    finding = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        (AuditFinding.finding_id == finding_identifier) | (AuditFinding.id == (int(finding_identifier) if finding_identifier.isdigit() else -1))
    ).first()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit finding not found.")

    check_org_access(current_user, finding.organization_id, request=request)

    finding.status = close_in.resolution_status
    finding.closed_at = datetime.now(timezone.utc)
    finding.closed_by_id = current_user.id

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="FINDING_CLOSED",
        resource_type="AuditFinding",
        resource_id=finding.id,
        details=f'{{"finding_id": "{finding.finding_id}", "status": "{finding.status.value}", "notes": "{close_in.closure_notes}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(finding)

    log_security_event(
        event_type="FINDING_CLOSED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Finding:{finding.finding_id}->{finding.status.value}"
    )

    return format_finding_response(finding)


# ==============================================================================
# Module G & H: Web UI HTML Views
# ==============================================================================

@router.get("/findings", response_class=HTMLResponse)
async def web_findings_dashboard(
    request: Request,
    status_filter: Optional[str] = Query(None),
    severity_filter: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Audit Findings & CAPA Remediation Tracker dashboard (Modules G & H).
    """
    org_id = current_user.organization_id if current_user else 1

    query = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id
    ).options(
        joinedload(AuditFinding.control),
        joinedload(AuditFinding.control_test),
        joinedload(AuditFinding.owner),
        joinedload(AuditFinding.closed_by),
        joinedload(AuditFinding.corrective_actions)
    )

    if status_filter and status_filter in [s.value for s in FindingStatus]:
        query = query.filter(AuditFinding.status == FindingStatus(status_filter))

    if severity_filter and severity_filter in [s.value for s in FindingSeverity]:
        query = query.filter(AuditFinding.severity == FindingSeverity(severity_filter))

    findings = query.order_by(AuditFinding.created_at.desc()).all()

    all_org_findings = db.query(AuditFinding).filter(AuditFinding.organization_id == org_id).all()
    counts = {
        "ALL": len(all_org_findings),
        "OPEN": sum(1 for f in all_org_findings if f.status == FindingStatus.OPEN),
        "REMEDIATION_IN_PROGRESS": sum(1 for f in all_org_findings if f.status == FindingStatus.REMEDIATION_IN_PROGRESS),
        "RETESTING": sum(1 for f in all_org_findings if f.status == FindingStatus.RETESTING),
        "CLOSED": sum(1 for f in all_org_findings if f.status == FindingStatus.CLOSED),
        "RISK_ACCEPTED": sum(1 for f in all_org_findings if f.status == FindingStatus.RISK_ACCEPTED),
        "CRITICAL": sum(1 for f in all_org_findings if f.severity == FindingSeverity.CRITICAL and f.status != FindingStatus.CLOSED),
        "HIGH": sum(1 for f in all_org_findings if f.severity == FindingSeverity.HIGH and f.status != FindingStatus.CLOSED),
    }

    all_controls = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id).all()
    all_tests = db.query(ControlTest).filter(ControlTest.organization_id == org_id).all()
    all_users = db.query(User).filter((User.organization_id == org_id) | (User.organization_id == None)).all()

    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "findings": findings,
            "controls": all_controls,
            "tests": all_tests,
            "users": all_users,
            "counts": counts,
            "active_status": status_filter or "ALL",
            "active_severity": severity_filter or "ALL",
            "title": "Audit Findings & CAPA Remediation | CyberGRC"
        }
    )


@router.get("/findings/{finding_identifier}", response_class=HTMLResponse)
async def web_finding_detail(
    finding_identifier: str,
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders single finding deep-dive root-cause analysis and CAPA tracking page.
    """
    org_id = current_user.organization_id if current_user else 1

    finding = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        (AuditFinding.finding_id == finding_identifier) | (AuditFinding.id == (int(finding_identifier) if finding_identifier.isdigit() else -1))
    ).options(
        joinedload(AuditFinding.control),
        joinedload(AuditFinding.control_test),
        joinedload(AuditFinding.owner),
        joinedload(AuditFinding.closed_by),
        joinedload(AuditFinding.corrective_actions).joinedload(CorrectiveAction.owner)
    ).first()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit finding not found.")

    all_users = db.query(User).filter((User.organization_id == org_id) | (User.organization_id == None)).all()

    return templates.TemplateResponse(
        request=request,
        name="finding_detail.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "finding": finding,
            "users": all_users,
            "title": f"Finding {finding.finding_id}: {finding.title} | CyberGRC"
        }
    )


@router.post("/findings/create", response_class=RedirectResponse)
async def web_create_finding_form(
    request: Request,
    finding_id: str = Form(...),
    control_id: int = Form(...),
    title: str = Form(...),
    severity: str = Form("MEDIUM"),
    root_cause: str = Form(...),
    business_impact: str = Form(...),
    owner_id: Optional[int] = Form(None),
    due_date: Optional[str] = Form(None),
    control_test_id: Optional[int] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML form submission for creating a new audit finding.
    """
    org_id = current_user.organization_id or 1
    due_dt = datetime.fromisoformat(due_date) if due_date else None

    new_finding = AuditFinding(
        organization_id=org_id,
        finding_id=finding_id.strip(),
        control_id=control_id,
        control_test_id=control_test_id or None,
        title=title.strip(),
        severity=FindingSeverity(severity),
        root_cause=root_cause.strip(),
        business_impact=business_impact.strip(),
        owner_id=owner_id or current_user.id,
        due_date=due_dt,
        status=FindingStatus.OPEN
    )
    db.add(new_finding)
    db.commit()

    return RedirectResponse(url=f"/findings/{new_finding.finding_id}", status_code=status.HTTP_302_FOUND)


@router.post("/findings/{finding_identifier}/actions", response_class=RedirectResponse)
async def web_create_action_form(
    finding_identifier: str,
    request: Request,
    action_plan: str = Form(...),
    owner_id: Optional[int] = Form(None),
    target_completion_date: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML form submission to attach a corrective action plan to a finding.
    """
    org_id = current_user.organization_id or 1
    finding = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        (AuditFinding.finding_id == finding_identifier) | (AuditFinding.id == (int(finding_identifier) if finding_identifier.isdigit() else -1))
    ).first()

    if finding:
        target_dt = datetime.fromisoformat(target_completion_date) if target_completion_date else None
        new_action = CorrectiveAction(
            organization_id=org_id,
            finding_id=finding.id,
            action_plan=action_plan.strip(),
            owner_id=owner_id or current_user.id,
            target_completion_date=target_dt,
            status=ActionStatus.OPEN,
            notes=notes.strip() if notes else None
        )
        db.add(new_action)
        if finding.status == FindingStatus.OPEN:
            finding.status = FindingStatus.REMEDIATION_IN_PROGRESS
        db.commit()

    return RedirectResponse(url=f"/findings/{finding_identifier}", status_code=status.HTTP_302_FOUND)


@router.post("/findings/{finding_identifier}/actions/{action_id}/update", response_class=RedirectResponse)
async def web_update_action_status_form(
    finding_identifier: str,
    action_id: int,
    request: Request,
    status_val: str = Form(...),
    notes: Optional[str] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML form submission to update a corrective action status.
    """
    org_id = current_user.organization_id or 1
    action = db.query(CorrectiveAction).filter(
        CorrectiveAction.id == action_id,
        CorrectiveAction.organization_id == org_id
    ).first()

    if action:
        action.status = ActionStatus(status_val)
        if action.status in [ActionStatus.IMPLEMENTED, ActionStatus.VERIFIED] and not action.actual_completion_date:
            action.actual_completion_date = datetime.now(timezone.utc)
        if notes:
            action.notes = notes.strip()
        db.commit()

    return RedirectResponse(url=f"/findings/{finding_identifier}", status_code=status.HTTP_302_FOUND)


@router.post("/findings/{finding_identifier}/close", response_class=RedirectResponse)
async def web_close_finding_form(
    finding_identifier: str,
    request: Request,
    closure_notes: str = Form(...),
    resolution_status: str = Form("CLOSED"),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML form submission for formal closure sign-off of an audit finding.
    """
    org_id = current_user.organization_id or 1
    finding = db.query(AuditFinding).filter(
        AuditFinding.organization_id == org_id,
        (AuditFinding.finding_id == finding_identifier) | (AuditFinding.id == (int(finding_identifier) if finding_identifier.isdigit() else -1))
    ).first()

    if finding:
        finding.status = FindingStatus(resolution_status)
        finding.closed_at = datetime.now(timezone.utc)
        finding.closed_by_id = current_user.id

        audit_evt = AuditEvent(
            organization_id=org_id,
            user_id=current_user.id,
            action="FINDING_CLOSED",
            resource_type="AuditFinding",
            resource_id=finding.id,
            details=f'{{"finding_id": "{finding.finding_id}", "status": "{finding.status.value}", "notes": "{closure_notes}"}}',
            ip_address=request.client.host if request.client else "unknown"
        )
        db.add(audit_evt)
        db.commit()

    return RedirectResponse(url=f"/findings/{finding_identifier}", status_code=status.HTTP_302_FOUND)
