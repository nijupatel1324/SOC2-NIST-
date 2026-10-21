from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import log_security_event
from app.core.auth import get_current_user, get_current_user_optional
from app.db.session import get_db
from app.models import User
from app.services.report_service import (
    compile_executive_readiness_metrics,
    generate_markdown_readiness_report
)

router = APIRouter(tags=["Executive Dashboard & Readiness Reporting"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


# ==============================================================================
# Module H: REST API Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/reports/readiness")
async def api_readiness_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns enterprise-wide compliance readiness metrics, risk reduction %,
    evidence coverage, and deficiency statistics.
    """
    org_id = current_user.organization_id or 1
    metrics = compile_executive_readiness_metrics(db, org_id)

    # Convert complex objects for clean JSON serialization
    serialized_frameworks = [
        {
            "code": f.framework_code,
            "name": f.framework_name,
            "total": f.total_requirements,
            "applicable": f.applicable_requirements,
            "implemented": f.implemented_count,
            "gaps": f.gap_count,
            "strict_pct": f.strict_readiness_pct,
            "weighted_pct": f.weighted_readiness_pct,
            "assurance_type": f.assurance_type
        }
        for f in metrics["frameworks"]
    ]

    return {
        "organization_name": metrics["organization_name"],
        "generated_at": metrics["generated_at"].isoformat(),
        "soc2_readiness_pct": metrics["soc2_readiness"],
        "iso27001_readiness_pct": metrics["iso27001_readiness"],
        "nist_csf_readiness_pct": metrics["nist_csf_readiness"],
        "risk_reduction_pct": metrics["risk_reduction_pct"],
        "frameworks": serialized_frameworks,
        "controls": metrics["controls"],
        "tests": metrics["tests"],
        "findings": metrics["findings"],
        "regulatory_disclaimer": (
            "This report is an internal readiness assessment and does not constitute an official "
            "SOC 2 examination report issued by an independent CPA firm under AICPA standards, "
            "nor an accredited ISO 27001 certification. NIST CSF 2.0 is voluntary guidance."
        )
    }


@router.get(f"{settings.API_V1_STR}/reports/export")
async def api_export_markdown_report(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Generates and downloads a complete Markdown compliance readiness report.
    """
    org_id = current_user.organization_id or 1
    metrics = compile_executive_readiness_metrics(db, org_id)
    md_content = generate_markdown_readiness_report(metrics)

    log_security_event(
        event_type="REPORT_DOWNLOADED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource="Report:ExecutiveReadinessMarkdown"
    )

    filename = f"cybergrc_readiness_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.md"
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# ==============================================================================
# Module H: Web UI HTML Views
# ==============================================================================

@router.get("/dashboard", response_class=HTMLResponse)
@router.get("/reports/dashboard", response_class=HTMLResponse)
async def web_executive_dashboard(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Executive Compliance & Audit Readiness Dashboard (Module H).
    """
    org_id = current_user.organization_id if current_user else 1
    metrics = compile_executive_readiness_metrics(db, org_id)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "metrics": metrics,
            "title": "Executive Compliance Dashboard | CyberGRC"
        }
    )


@router.get("/reports/executive", response_class=HTMLResponse)
async def web_executive_report_printable(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders print-ready Executive Readiness Report suitable for PDF export.
    """
    org_id = current_user.organization_id if current_user else 1
    metrics = compile_executive_readiness_metrics(db, org_id)

    return templates.TemplateResponse(
        request=request,
        name="executive_report.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "metrics": metrics,
            "title": f"Executive Readiness Report - {metrics['organization_name']}"
        }
    )
