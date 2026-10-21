from typing import Tuple, List
from sqlalchemy.orm import Session
from app.models import RiskAssessment, RiskLevel, User
from app.schemas.risk import (
    RiskResponse,
    RiskMatrixCell,
    RiskMatrixSummary,
    calculate_risk_level
)


def compute_risk_score_and_level(likelihood: int, impact: int) -> Tuple[int, RiskLevel]:
    """
    Computes numerical risk score (1 to 25) and categorical risk level
    using standard 5x5 Likelihood x Impact matrix.
    """
    score = max(1, min(5, likelihood)) * max(1, min(5, impact))
    level = calculate_risk_level(score)
    return score, level


def format_risk_response(risk: RiskAssessment) -> RiskResponse:
    """Helper to convert RiskAssessment ORM entity to RiskResponse schema."""
    return RiskResponse(
        id=risk.id,
        organization_id=risk.organization_id,
        risk_id=risk.risk_id,
        title=risk.title,
        affected_asset=risk.affected_asset,
        threat_source=risk.threat_source,
        vulnerability=risk.vulnerability,
        business_impact=risk.business_impact,
        owner_id=risk.owner_id,
        owner_name=risk.owner.full_name if risk.owner else None,
        owner_email=risk.owner.email if risk.owner else None,
        inherent_likelihood=risk.inherent_likelihood,
        inherent_impact=risk.inherent_impact,
        inherent_score=risk.inherent_score,
        inherent_level=risk.inherent_level,
        existing_safeguards=risk.existing_safeguards,
        residual_likelihood=risk.residual_likelihood,
        residual_impact=risk.residual_impact,
        residual_score=risk.residual_score,
        residual_level=risk.residual_level,
        treatment_strategy=risk.treatment_strategy,
        treatment_details=risk.treatment_details,
        risk_acceptance_rationale=risk.risk_acceptance_rationale,
        risk_accepted_by_id=risk.risk_accepted_by_id,
        risk_accepted_by_name=risk.risk_accepted_by.full_name if risk.risk_accepted_by else None,
        risk_accepted_at=risk.risk_accepted_at,
        status=risk.status,
        created_at=risk.created_at,
        updated_at=risk.updated_at
    )


def get_risk_matrix_summary(db: Session, org_id: int) -> RiskMatrixSummary:
    """
    Aggregates the entire enterprise risk register into a 5x5 Heatmap Matrix.
    Compares Inherent vs Residual risk distributions and calculates overall risk reduction %.
    """
    risks = db.query(RiskAssessment).filter(
        RiskAssessment.organization_id == org_id
    ).order_by(RiskAssessment.risk_id).all()

    total_risks = len(risks)
    cells: List[RiskMatrixCell] = []

    # Build 5x5 grid: Impact 5 (top) down to 1 (bottom), Likelihood 1 (left) to 5 (right)
    for impact in range(5, 0, -1):
        for likelihood in range(1, 6):
            score, level = compute_risk_score_and_level(likelihood, impact)

            inh_matching = [r.risk_id for r in risks if r.inherent_likelihood == likelihood and r.inherent_impact == impact]
            res_matching = [r.risk_id for r in risks if r.residual_likelihood == likelihood and r.residual_impact == impact]

            cells.append(
                RiskMatrixCell(
                    likelihood=likelihood,
                    impact=impact,
                    score=score,
                    level=level.value,
                    inherent_count=len(inh_matching),
                    residual_count=len(res_matching),
                    inherent_risks=inh_matching,
                    residual_risks=res_matching
                )
            )

    inh_crit = sum(1 for r in risks if r.inherent_level == RiskLevel.CRITICAL)
    inh_high = sum(1 for r in risks if r.inherent_level == RiskLevel.HIGH)
    inh_med = sum(1 for r in risks if r.inherent_level == RiskLevel.MEDIUM)
    inh_low = sum(1 for r in risks if r.inherent_level == RiskLevel.LOW)

    res_crit = sum(1 for r in risks if r.residual_level == RiskLevel.CRITICAL)
    res_high = sum(1 for r in risks if r.residual_level == RiskLevel.HIGH)
    res_med = sum(1 for r in risks if r.residual_level == RiskLevel.MEDIUM)
    res_low = sum(1 for r in risks if r.residual_level == RiskLevel.LOW)

    total_inh_score = sum(r.inherent_score for r in risks)
    total_res_score = sum(r.residual_score for r in risks)

    avg_inh = round(total_inh_score / total_risks, 1) if total_risks > 0 else 0.0
    avg_res = round(total_res_score / total_risks, 1) if total_risks > 0 else 0.0

    if total_inh_score > 0:
        reduction_pct = round(((total_inh_score - total_res_score) / total_inh_score) * 100.0, 1)
    else:
        reduction_pct = 0.0

    return RiskMatrixSummary(
        matrix=cells,
        total_risks=total_risks,
        inherent_critical_count=inh_crit,
        inherent_high_count=inh_high,
        inherent_medium_count=inh_med,
        inherent_low_count=inh_low,
        residual_critical_count=res_crit,
        residual_high_count=res_high,
        residual_medium_count=res_med,
        residual_low_count=res_low,
        average_inherent_score=avg_inh,
        average_residual_score=avg_res,
        risk_reduction_pct=reduction_pct
    )
