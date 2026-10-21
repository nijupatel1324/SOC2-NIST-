from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.models.enums import RiskLevel, RiskTreatmentStrategy, RiskStatus


def calculate_risk_level(score: int) -> RiskLevel:
    """
    Standard 5x5 matrix scoring conversion:
    - 20 to 25: CRITICAL
    - 12 to 19: HIGH
    - 6 to 11:  MEDIUM
    - 1 to 5:   LOW
    """
    if score >= 20:
        return RiskLevel.CRITICAL
    elif score >= 12:
        return RiskLevel.HIGH
    elif score >= 6:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


class RiskBase(BaseModel):
    risk_id: str = Field(..., min_length=3, max_length=50, description="Unique risk identifier (e.g. RSK-2026-001)")
    title: str = Field(..., min_length=3, max_length=255, description="Clear description of the risk event")
    affected_asset: str = Field(..., min_length=2, max_length=255, description="Impacted system, service, or data asset")
    threat_source: str = Field(..., min_length=2, max_length=255, description="Adversary, insider, supply chain, environmental")
    vulnerability: str = Field(..., min_length=5, description="Technical flaw, misconfiguration, or missing safeguard")
    business_impact: str = Field(..., min_length=5, description="Operational, financial, legal, or reputational consequence")
    owner_id: Optional[int] = Field(None, description="Responsible risk owner user ID")

    # Inherent Risk Rating (1 to 5)
    inherent_likelihood: int = Field(..., ge=1, le=5, description="1=Rare, 2=Unlikely, 3=Possible, 4=Likely, 5=Almost Certain")
    inherent_impact: int = Field(..., ge=1, le=5, description="1=Insignificant, 2=Minor, 3=Moderate, 4=Major, 5=Catastrophic")

    # Safeguards
    existing_safeguards: Optional[str] = Field(None, description="Currently implemented controls mitigating this risk")

    # Residual Risk Rating (1 to 5)
    residual_likelihood: int = Field(..., ge=1, le=5, description="Likelihood after planned or active treatment")
    residual_impact: int = Field(..., ge=1, le=5, description="Impact after planned or active treatment")

    # Treatment Strategy
    treatment_strategy: RiskTreatmentStrategy = RiskTreatmentStrategy.MITIGATE
    treatment_details: str = Field(..., min_length=5, description="Specific control remediation or treatment action plan")
    status: RiskStatus = RiskStatus.IDENTIFIED


class RiskCreate(RiskBase):
    risk_acceptance_rationale: Optional[str] = None


class RiskUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=255)
    affected_asset: Optional[str] = Field(None, min_length=2, max_length=255)
    threat_source: Optional[str] = Field(None, min_length=2, max_length=255)
    vulnerability: Optional[str] = Field(None, min_length=5)
    business_impact: Optional[str] = Field(None, min_length=5)
    owner_id: Optional[int] = None
    inherent_likelihood: Optional[int] = Field(None, ge=1, le=5)
    inherent_impact: Optional[int] = Field(None, ge=1, le=5)
    existing_safeguards: Optional[str] = None
    residual_likelihood: Optional[int] = Field(None, ge=1, le=5)
    residual_impact: Optional[int] = Field(None, ge=1, le=5)
    treatment_strategy: Optional[RiskTreatmentStrategy] = None
    treatment_details: Optional[str] = Field(None, min_length=5)
    status: Optional[RiskStatus] = None
    risk_acceptance_rationale: Optional[str] = None


class RiskAcceptanceRequest(BaseModel):
    rationale: str = Field(
        ...,
        min_length=10,
        description="Formal business rationale and executive justification for accepting this cybersecurity risk"
    )


class RiskResponse(RiskBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    inherent_score: int
    inherent_level: RiskLevel
    residual_score: int
    residual_level: RiskLevel
    risk_acceptance_rationale: Optional[str] = None
    risk_accepted_by_id: Optional[int] = None
    risk_accepted_by_name: Optional[str] = None
    risk_accepted_at: Optional[datetime] = None
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RiskMatrixCell(BaseModel):
    likelihood: int
    impact: int
    score: int
    level: str
    inherent_count: int
    residual_count: int
    inherent_risks: List[str]
    residual_risks: List[str]


class RiskMatrixSummary(BaseModel):
    """
    Standard 5x5 Risk Heatmap Matrix data distribution.
    Compares inherent vs residual risk exposure across the enterprise.
    """
    matrix: List[RiskMatrixCell]
    total_risks: int
    inherent_critical_count: int
    inherent_high_count: int
    inherent_medium_count: int
    inherent_low_count: int
    residual_critical_count: int
    residual_high_count: int
    residual_medium_count: int
    residual_low_count: int
    average_inherent_score: float
    average_residual_score: float
    risk_reduction_pct: float
