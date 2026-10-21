from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session, joinedload
from app.models import (
    Framework,
    FrameworkRequirement,
    ComplianceAssessment,
    SecurityControl,
    ControlMapping,
    AssessmentStatus,
    MappingApprovalStatus
)
from app.schemas.assessment import AssessmentFrameworkSummary, AssessmentResponse, MappedControlSummary
from app.schemas.mapping import CrossFrameworkMatrixRow


def get_framework_readiness_summaries(db: Session, org_id: int) -> List[AssessmentFrameworkSummary]:
    """
    Computes rigorous compliance readiness metrics for each framework.
    Avoids arbitrary single-percentage reporting by clearly specifying the
    mathematical formula, applicable denominator, and non-certification boundaries.
    """
    frameworks = db.query(Framework).options(
        joinedload(Framework.requirements).joinedload(FrameworkRequirement.assessments)
    ).order_by(Framework.code).all()

    summaries = []

    for fw in frameworks:
        reqs = fw.requirements
        total_reqs = len(reqs)

        not_applicable = 0
        implemented = 0
        partially_implemented = 0
        needs_improvement = 0
        not_implemented = 0
        not_assessed = 0

        # Map assessments for the target organization
        for req in reqs:
            # Find assessment matching org_id
            ass = next((a for a in req.assessments if a.organization_id == org_id), None)
            if not ass or ass.status == AssessmentStatus.NOT_ASSESSED:
                not_assessed += 1
            elif ass.status == AssessmentStatus.NOT_APPLICABLE:
                not_applicable += 1
            elif ass.status == AssessmentStatus.IMPLEMENTED:
                implemented += 1
            elif ass.status == AssessmentStatus.PARTIALLY_IMPLEMENTED:
                partially_implemented += 1
            elif ass.status == AssessmentStatus.NEEDS_IMPROVEMENT:
                needs_improvement += 1
            elif ass.status == AssessmentStatus.NOT_IMPLEMENTED:
                not_implemented += 1

        applicable = total_reqs - not_applicable
        if applicable > 0:
            strict_pct = round((implemented / applicable) * 100.0, 1)
            weighted_pct = round(((implemented + (0.5 * partially_implemented)) / applicable) * 100.0, 1)
        else:
            strict_pct = 100.0
            weighted_pct = 100.0

        gap_count = not_implemented + partially_implemented + needs_improvement

        if fw.code == "SOC2":
            scope = (
                "In-Scope: AICPA SOC 2 Trust Services Criteria (Common Criteria CC1.1 - CC9.2). "
                "Readiness evaluates internal controls prior to formal Type I / Type II examination by an independent CPA firm."
            )
        elif fw.code == "ISO27001":
            scope = (
                "In-Scope: ISO/IEC 27001:2022 Information Security Management System (ISMS) Annex A controls (A.5, A.7, A.8). "
                "Readiness evaluates control operational effectiveness prior to external Stage 1 & Stage 2 registrar audits."
            )
        else:
            scope = (
                "In-Scope: NIST Cybersecurity Framework (CSF) 2.0 Core Outcomes across GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER. "
                "Voluntary guidance for internal risk posture and tier self-assessment (Non-certifiable)."
            )

        formula = (
            f"Strict Readiness = (Fully Implemented [{implemented}] / Applicable [{applicable}]) × 100% = {strict_pct}%. "
            f"Weighted Readiness credits 50% for Partially Implemented controls ({partially_implemented} × 0.5) = {weighted_pct}%. "
            f"Applicable Denominator = Total [{total_reqs}] - Formally Justified Not Applicable [{not_applicable}]."
        )

        summaries.append(
            AssessmentFrameworkSummary(
                framework_code=fw.code,
                framework_name=fw.name,
                framework_version=fw.version,
                issuing_body=fw.issuing_body,
                is_certification=fw.is_certification,
                assurance_type=fw.assurance_type,
                total_requirements=total_reqs,
                not_applicable_count=not_applicable,
                applicable_requirements=applicable,
                implemented_count=implemented,
                partially_implemented_count=partially_implemented,
                needs_improvement_count=needs_improvement,
                not_implemented_count=not_implemented,
                not_assessed_count=not_assessed,
                strict_readiness_pct=strict_pct,
                weighted_readiness_pct=weighted_pct,
                gap_count=gap_count,
                formula_explanation=formula,
                scope_definition=scope
            )
        )

    return summaries


def get_cross_framework_matrix(db: Session, org_id: int) -> List[CrossFrameworkMatrixRow]:
    """
    Builds the Cross-Framework Mapping Matrix (Module C).
    Displays internal controls alongside their corresponding mappings
    to SOC 2, ISO 27001, and NIST CSF 2.0 requirements side-by-side.
    """
    controls = db.query(SecurityControl).filter(
        SecurityControl.organization_id == org_id
    ).options(
        joinedload(SecurityControl.mappings).joinedload(ControlMapping.requirement).joinedload(FrameworkRequirement.framework)
    ).order_by(SecurityControl.control_id).all()

    matrix_rows = []
    for ctrl in controls:
        soc2_maps = []
        iso_maps = []
        nist_maps = []

        for m in ctrl.mappings:
            status_suffix = "" if m.approval_status == MappingApprovalStatus.APPROVED else f" ({m.approval_status.value})"
            label = f"{m.requirement.identifier} - {m.requirement.title}{status_suffix}"
            if m.requirement.framework.code == "SOC2":
                soc2_maps.append(label)
            elif m.requirement.framework.code == "ISO27001":
                iso_maps.append(label)
            elif m.requirement.framework.code == "NIST_CSF":
                nist_maps.append(label)

        matrix_rows.append(
            CrossFrameworkMatrixRow(
                control_id=ctrl.control_id,
                control_name=ctrl.name,
                control_status=ctrl.implementation_status.value,
                soc2_mappings=soc2_maps,
                iso27001_mappings=iso_maps,
                nist_csf_mappings=nist_maps,
                total_mappings=len(ctrl.mappings)
            )
        )

    return matrix_rows


def format_assessment_response(assessment: ComplianceAssessment, requirement: FrameworkRequirement) -> AssessmentResponse:
    """Helper to convert ComplianceAssessment ORM object to AssessmentResponse schema."""
    mapped_controls = []
    for m in requirement.mappings:
        mapped_controls.append(
            MappedControlSummary(
                id=m.control.id,
                control_id=m.control.control_id,
                name=m.control.name,
                implementation_status=m.control.implementation_status.value
            )
        )

    return AssessmentResponse(
        id=assessment.id,
        organization_id=assessment.organization_id,
        requirement_id=requirement.id,
        framework_code=requirement.framework.code,
        framework_name=requirement.framework.name,
        requirement_identifier=requirement.identifier,
        requirement_title=requirement.title,
        requirement_category=requirement.category,
        requirement_guidance=requirement.guidance,
        status=assessment.status,
        justification=assessment.justification,
        assessed_by_id=assessment.assessed_by_id,
        assessed_by_name=assessment.assessed_by.full_name if assessment.assessed_by else None,
        identified_gaps=assessment.identified_gaps,
        recommended_actions=assessment.recommended_actions,
        assessed_at=assessment.assessed_at,
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
        mapped_controls_count=len(mapped_controls),
        mapped_controls=mapped_controls
    )
