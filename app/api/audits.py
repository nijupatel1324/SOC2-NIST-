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
    AuditProject,
    ControlTest,
    SecurityControl,
    Framework,
    EvidenceRecord,
    User,
    UserRole,
    TestResult,
    AuditEvent
)
from app.schemas.audit import (
    AuditProjectCreate,
    AuditProjectResponse,
    ControlTestCreate,
    ControlTestResponse
)
from app.services.evidence_service import (
    format_audit_project_response,
    format_control_test_response
)

router = APIRouter(tags=["Audit Projects & Control Testing"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


# ==============================================================================
# Module G: REST API Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/audits/projects", response_model=List[AuditProjectResponse])
async def api_list_audit_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists audit projects and compliance review campaigns for the user's organization.
    """
    org_id = current_user.organization_id or 1
    projects = db.query(AuditProject).filter(
        AuditProject.organization_id == org_id
    ).options(
        joinedload(AuditProject.framework),
        joinedload(AuditProject.lead_auditor),
        joinedload(AuditProject.tests)
    ).order_by(AuditProject.created_at.desc()).all()

    return [format_audit_project_response(p) for p in projects]


@router.post(f"{settings.API_V1_STR}/audits/projects", response_model=AuditProjectResponse, status_code=status.HTTP_201_CREATED)
async def api_create_audit_project(
    project_in: AuditProjectCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Creates a new audit project campaign.
    """
    org_id = current_user.organization_id or 1

    fw = db.query(Framework).filter(Framework.id == project_in.framework_id).first()
    if not fw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Framework not found.")

    new_project = AuditProject(
        organization_id=org_id,
        name=project_in.name.strip(),
        framework_id=project_in.framework_id,
        audit_type=project_in.audit_type.strip(),
        period_start=project_in.period_start,
        period_end=project_in.period_end,
        lead_auditor_id=project_in.lead_auditor_id or current_user.id,
        status=project_in.status
    )
    db.add(new_project)
    db.flush()

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="AUDIT_PROJECT_CREATED",
        resource_type="AuditProject",
        resource_id=new_project.id,
        details=f'{{"name": "{new_project.name}", "framework": "{fw.code}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_project)

    return format_audit_project_response(new_project)


@router.get(f"{settings.API_V1_STR}/audits/tests", response_model=List[ControlTestResponse])
async def api_list_control_tests(
    project_id: Optional[int] = None,
    control_id: Optional[int] = None,
    result: Optional[TestResult] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists control tests executed during internal or external audits.
    """
    org_id = current_user.organization_id or 1
    query = db.query(ControlTest).filter(
        ControlTest.organization_id == org_id
    ).options(
        joinedload(ControlTest.audit_project),
        joinedload(ControlTest.control),
        joinedload(ControlTest.tested_by),
        joinedload(ControlTest.evidence)
    )

    if project_id:
        query = query.filter(ControlTest.audit_project_id == project_id)

    if control_id:
        query = query.filter(ControlTest.control_id == control_id)

    if result:
        query = query.filter(ControlTest.result == result)

    tests = query.order_by(ControlTest.created_at.desc()).all()
    return [format_control_test_response(t) for t in tests]


@router.post(f"{settings.API_V1_STR}/audits/tests", response_model=ControlTestResponse, status_code=status.HTTP_201_CREATED)
async def api_create_control_test(
    test_in: ControlTestCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Records the outcome of a control testing procedure (PASS, FAIL, PENDING, INCONCLUSIVE).
    Automatically updates the control's last_tested_at timestamp.
    """
    org_id = current_user.organization_id or 1

    ctrl = db.query(SecurityControl).filter(
        SecurityControl.id == test_in.control_id,
        SecurityControl.organization_id == org_id
    ).first()
    if not ctrl:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target security control not found.")

    new_test = ControlTest(
        organization_id=org_id,
        audit_project_id=test_in.audit_project_id,
        control_id=test_in.control_id,
        test_title=test_in.test_title.strip(),
        test_objective=test_in.test_objective.strip(),
        test_procedure=test_in.test_procedure.strip(),
        result=test_in.result,
        tested_by_id=current_user.id,
        tested_at=datetime.now(timezone.utc),
        sample_size=test_in.sample_size,
        exceptions_identified=test_in.exceptions_identified,
        evidence_id=test_in.evidence_id,
        notes=test_in.notes.strip() if test_in.notes else None
    )
    db.add(new_test)

    # Update control's last_tested_at date
    ctrl.last_tested_at = datetime.now(timezone.utc)
    db.flush()

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="CONTROL_TEST_RECORDED",
        resource_type="ControlTest",
        resource_id=new_test.id,
        details=f'{{"control_id": "{ctrl.control_id}", "result": "{new_test.result.value}", "exceptions": {new_test.exceptions_identified}}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_test)

    log_security_event(
        event_type="CONTROL_TESTED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"ControlTest:{ctrl.control_id}->{new_test.result.value}"
    )

    return format_control_test_response(new_test)


@router.get(f"{settings.API_V1_STR}/audits/tests/{{test_id}}", response_model=ControlTestResponse)
async def api_get_control_test(
    test_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves single control test execution record.
    """
    org_id = current_user.organization_id or 1
    test = db.query(ControlTest).filter(
        ControlTest.id == test_id,
        ControlTest.organization_id == org_id
    ).options(
        joinedload(ControlTest.audit_project),
        joinedload(ControlTest.control),
        joinedload(ControlTest.tested_by),
        joinedload(ControlTest.evidence)
    ).first()

    if not test:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control test not found.")

    check_org_access(current_user, test.organization_id, request=request)
    return format_control_test_response(test)


# ==============================================================================
# Module G: Web UI HTML Views
# ==============================================================================

@router.get("/audits", response_class=HTMLResponse)
async def web_audits_dashboard(
    request: Request,
    result_filter: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Audit Campaigns & Control Testing Execution dashboard (Module G).
    """
    org_id = current_user.organization_id if current_user else 1

    projects = db.query(AuditProject).filter(
        AuditProject.organization_id == org_id
    ).options(
        joinedload(AuditProject.framework),
        joinedload(AuditProject.lead_auditor),
        joinedload(AuditProject.tests)
    ).all()

    query = db.query(ControlTest).filter(
        ControlTest.organization_id == org_id
    ).options(
        joinedload(ControlTest.audit_project),
        joinedload(ControlTest.control),
        joinedload(ControlTest.tested_by),
        joinedload(ControlTest.evidence)
    )

    if result_filter and result_filter in [r.value for r in TestResult]:
        query = query.filter(ControlTest.result == TestResult(result_filter))

    tests = query.order_by(ControlTest.created_at.desc()).all()

    all_controls = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id).all()
    all_frameworks = db.query(Framework).all()
    all_evidence = db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == org_id).all()

    all_org_tests = db.query(ControlTest).filter(ControlTest.organization_id == org_id).all()
    counts = {
        "ALL": len(all_org_tests),
        "PASS": sum(1 for t in all_org_tests if t.result == TestResult.PASS),
        "FAIL": sum(1 for t in all_org_tests if t.result == TestResult.FAIL),
        "PENDING": sum(1 for t in all_org_tests if t.result == TestResult.PENDING),
        "INCONCLUSIVE": sum(1 for t in all_org_tests if t.result == TestResult.INCONCLUSIVE),
    }

    return templates.TemplateResponse(
        request=request,
        name="audits.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "projects": projects,
            "tests": tests,
            "controls": all_controls,
            "frameworks": all_frameworks,
            "evidence": all_evidence,
            "counts": counts,
            "active_result": result_filter or "ALL",
            "title": "Audit Projects & Control Testing | CyberGRC"
        }
    )


@router.post("/audits/projects", response_class=RedirectResponse)
async def web_create_audit_project_form(
    request: Request,
    name: str = Form(...),
    framework_id: int = Form(...),
    audit_type: str = Form("INTERNAL_READINESS"),
    period_start: str = Form(...),
    period_end: str = Form(...),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML form submission for creating a new audit campaign.
    """
    org_id = current_user.organization_id or 1
    start_dt = datetime.fromisoformat(period_start)
    end_dt = datetime.fromisoformat(period_end)

    new_project = AuditProject(
        organization_id=org_id,
        name=name.strip(),
        framework_id=framework_id,
        audit_type=audit_type.strip(),
        period_start=start_dt,
        period_end=end_dt,
        lead_auditor_id=current_user.id,
        status="IN_PROGRESS"
    )
    db.add(new_project)
    db.commit()

    return RedirectResponse(url="/audits", status_code=status.HTTP_302_FOUND)


@router.post("/audits/tests", response_class=RedirectResponse)
async def web_create_control_test_form(
    request: Request,
    control_id: int = Form(...),
    test_title: str = Form(...),
    test_objective: str = Form(...),
    test_procedure: str = Form(...),
    result: str = Form(...),
    sample_size: int = Form(0),
    exceptions_identified: int = Form(0),
    audit_project_id: Optional[int] = Form(None),
    evidence_id: Optional[int] = Form(None),
    notes: Optional[str] = Form(None),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML form submission for recording a control test execution.
    """
    org_id = current_user.organization_id or 1

    ctrl = db.query(SecurityControl).filter(
        SecurityControl.id == control_id,
        SecurityControl.organization_id == org_id
    ).first()

    if ctrl:
        new_test = ControlTest(
            organization_id=org_id,
            audit_project_id=audit_project_id or None,
            control_id=control_id,
            test_title=test_title.strip(),
            test_objective=test_objective.strip(),
            test_procedure=test_procedure.strip(),
            result=TestResult(result),
            tested_by_id=current_user.id,
            tested_at=datetime.now(timezone.utc),
            sample_size=sample_size,
            exceptions_identified=exceptions_identified,
            evidence_id=evidence_id or None,
            notes=notes.strip() if notes else None
        )
        db.add(new_test)
        ctrl.last_tested_at = datetime.now(timezone.utc)
        db.commit()

    return RedirectResponse(url="/audits", status_code=status.HTTP_302_FOUND)
