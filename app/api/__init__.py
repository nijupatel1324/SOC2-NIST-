"""
API and Web route handlers.
"""
from app.api.auth import router as auth_router
from app.api.controls import router as controls_router
from app.api.mappings import router as mappings_router
from app.api.assessments import router as assessments_router
from app.api.risks import router as risks_router
from app.api.evidence import router as evidence_router
from app.api.audits import router as audits_router
from app.api.findings import router as findings_router
from app.api.reports import router as reports_router

__all__ = [
    "auth_router",
    "controls_router",
    "mappings_router",
    "assessments_router",
    "risks_router",
    "evidence_router",
    "audits_router",
    "findings_router",
    "reports_router",
]


