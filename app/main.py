import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, status, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.logging import logger, log_security_event
from app.core.security_headers import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager: handles startup and shutdown tasks.
    """
    logger.info("Initializing Cybersecurity GRC Platform...")
    # Ensure evidence vault upload directory exists
    upload_path = settings.resolved_upload_dir
    logger.info(f"Evidence vault storage path: {upload_path}")
    logger.info(f"Active environment: {settings.ENVIRONMENT} | Debug mode: {settings.DEBUG}")
    logger.info(f"Database backend: {'SQLite' if settings.is_sqlite else 'PostgreSQL'}")

    log_security_event(
        event_type="SYSTEM_STARTUP",
        status="SUCCESS",
        details={
            "version": settings.PROJECT_VERSION,
            "environment": settings.ENVIRONMENT,
            "is_sqlite": settings.is_sqlite
        }
    )

    yield

    logger.info("Shutting down Cybersecurity GRC Platform...")
    log_security_event(
        event_type="SYSTEM_SHUTDOWN",
        status="SUCCESS"
    )


def create_application() -> FastAPI:
    """
    Application factory for the Cybersecurity GRC Platform.
    """
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.PROJECT_VERSION,
        description=(
            "Enterprise Cybersecurity GRC & Compliance Platform comparing, "
            "mapping, and managing controls across SOC 2, ISO/IEC 27001:2022, and NIST CSF 2.0."
        ),
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url="/api/redoc" if settings.DEBUG else None,
        openapi_url="/api/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan
    )

    # 1. Add OWASP Security Headers Middleware
    application.add_middleware(SecurityHeadersMiddleware)

    # 2. Mount Static Files
    if settings.STATIC_DIR.exists():
        application.mount("/static", StaticFiles(directory=settings.STATIC_DIR), name="static")

    # 3. Setup Jinja2 Templates
    templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)

    # 4. Root Presentation Route
    @application.get("/", response_class=HTMLResponse, tags=["Web"])
    async def index(request: Request):
        from app.db.session import SessionLocal
        from app.models import Organization, Framework, FrameworkRequirement, SecurityControl, ControlMapping, RiskAssessment, AuditFinding
        from app.core.auth import get_current_user_optional

        db = SessionLocal()
        user = None
        try:
            user = await get_current_user_optional(request, db=db)
            stats = {
                "org_count": db.query(Organization).count(),
                "framework_count": db.query(Framework).count(),
                "requirement_count": db.query(FrameworkRequirement).count(),
                "control_count": db.query(SecurityControl).count(),
                "mapping_count": db.query(ControlMapping).count(),
                "risk_count": db.query(RiskAssessment).count(),
                "finding_count": db.query(AuditFinding).count(),
            }
        except Exception:
            stats = {
                "org_count": 0,
                "framework_count": 0,
                "requirement_count": 0,
                "control_count": 0,
                "mapping_count": 0,
                "risk_count": 0,
                "finding_count": 0,
            }
        finally:
            db.close()

        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "settings": settings,
                "stats": stats,
                "user": user,
                "title": f"{settings.PROJECT_NAME} - Overview"
            }
        )

    # 5. Include API Routers
    from app.api.auth import router as auth_router
    from app.api.controls import router as controls_router
    from app.api.mappings import router as mappings_router
    from app.api.assessments import router as assessments_router
    from app.api.risks import router as risks_router
    from app.api.evidence import router as evidence_router
    from app.api.audits import router as audits_router
    from app.api.findings import router as findings_router
    from app.api.reports import router as reports_router
    application.include_router(auth_router)
    application.include_router(controls_router)
    application.include_router(mappings_router)
    application.include_router(assessments_router)
    application.include_router(risks_router)
    application.include_router(evidence_router)
    application.include_router(audits_router)
    application.include_router(findings_router)
    application.include_router(reports_router)



    # 6. Role-Guarded Test Endpoints for RBAC Verification
    from app.core.auth import require_role, get_current_user, check_org_access
    from app.models import User, UserRole

    @application.get("/api/v1/test/admin-only", tags=["RBAC Test"])
    async def admin_only_endpoint(current_user: User = Depends(require_role(UserRole.ORG_ADMIN))):
        return {"status": "authorized", "role": current_user.role.value, "user": current_user.email}

    @application.get("/api/v1/test/analyst-only", tags=["RBAC Test"])
    async def analyst_only_endpoint(current_user: User = Depends(require_role(UserRole.GRC_ANALYST))):
        return {"status": "authorized", "role": current_user.role.value, "user": current_user.email}

    @application.get("/api/v1/test/auditor-only", tags=["RBAC Test"])
    async def auditor_only_endpoint(current_user: User = Depends(require_role(UserRole.AUDITOR))):
        return {"status": "authorized", "role": current_user.role.value, "user": current_user.email}

    @application.get("/api/v1/test/org/{org_id}/resource", tags=["Multi-Tenancy Test"])
    async def tenant_isolated_endpoint(
        org_id: int,
        request: Request,
        current_user: User = Depends(get_current_user)
    ):
        check_org_access(current_user, target_org_id=org_id, request=request)
        return {"status": "authorized", "org_id": org_id, "user": current_user.email}

    # 5. Core API Health Endpoint
    @application.get("/api/health", tags=["Telemetry"])
    async def health_check():
        return {
            "status": "healthy",
            "project": settings.PROJECT_NAME,
            "version": settings.PROJECT_VERSION,
            "environment": settings.ENVIRONMENT,
            "database": "SQLite (Local Dev)" if settings.is_sqlite else "PostgreSQL (Enterprise)",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    # 6. Core API Readiness Endpoint
    @application.get("/api/ready", tags=["Telemetry"])
    async def readiness_check():
        upload_dir = settings.resolved_upload_dir
        writable = os.access(upload_dir, os.W_OK)
        return {
            "ready": writable,
            "checks": {
                "evidence_vault_writable": writable,
                "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_MB,
                "allowed_extensions": sorted(list(settings.allowed_extensions_set))
            }
        }

    # 7. Global 404 Handler
    @application.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "Resource not found", "path": request.url.path}
            )
        fallback_stats = {
            "org_count": 1,
            "framework_count": 3,
            "requirement_count": 0,
            "control_count": 0,
            "mapping_count": 0,
            "risk_count": 0,
            "finding_count": 0,
        }
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "settings": settings,
                "stats": fallback_stats,
                "user": None,
                "error": f"Page not found: {request.url.path}"
            },
            status_code=status.HTTP_404_NOT_FOUND
        )

    return application


app = create_application()
