from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, model_validator
from app.models.enums import AssessmentStatus


class AssessmentBase(BaseModel):
    requirement_id: int = Field(..., description="FrameworkRequirement database ID")
    status: AssessmentStatus = Field(
        default=AssessmentStatus.NOT_ASSESSED,
        description="6-state readiness status"
    )
    justification: Optional[str] = Field(
        None,
        description="Mandatory justification when status is NOT_APPLICABLE"
    )
    identified_gaps: Optional[str] = Field(
        None,
        description="Specific gaps or deficiencies preventing full compliance"
    )
    recommended_actions: Optional[str] = Field(
        None,
        description="Remediation steps or compensating controls to achieve compliance"
    )


class AssessmentCreate(AssessmentBase):
    @model_validator(mode="after")
    def validate_not_applicable_justification(self) -> "AssessmentCreate":
        if self.status == AssessmentStatus.NOT_APPLICABLE:
            if not self.justification or not self.justification.strip():
                raise ValueError("A documented justification is mandatory when marking a requirement as NOT_APPLICABLE.")
        return self


class AssessmentUpdate(BaseModel):
    status: Optional[AssessmentStatus] = None
    justification: Optional[str] = None
    identified_gaps: Optional[str] = None
    recommended_actions: Optional[str] = None

    @model_validator(mode="after")
    def validate_not_applicable_justification(self) -> "AssessmentUpdate":
        if self.status == AssessmentStatus.NOT_APPLICABLE:
            if not self.justification or not self.justification.strip():
                raise ValueError("A documented justification is mandatory when marking a requirement as NOT_APPLICABLE.")
        return self


class MappedControlSummary(BaseModel):
    id: int
    control_id: str
    name: str
    implementation_status: str


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    requirement_id: int
    framework_code: str
    framework_name: str
    requirement_identifier: str
    requirement_title: str
    requirement_category: str
    requirement_guidance: Optional[str] = None
    status: AssessmentStatus
    justification: Optional[str] = None
    assessed_by_id: Optional[int] = None
    assessed_by_name: Optional[str] = None
    identified_gaps: Optional[str] = None
    recommended_actions: Optional[str] = None
    assessed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    mapped_controls_count: int = 0
    mapped_controls: List[MappedControlSummary] = []


class AssessmentFrameworkSummary(BaseModel):
    """
    Standardized, transparent compliance readiness metric.
    Avoids arbitrary single-percentage reporting by clearly declaring
    the mathematical formula, scope, and applicable requirement count.
    """
    framework_code: str
    framework_name: str
    framework_version: str
    issuing_body: str
    is_certification: bool
    assurance_type: str
    total_requirements: int
    not_applicable_count: int
    applicable_requirements: int
    implemented_count: int
    partially_implemented_count: int
    needs_improvement_count: int
    not_implemented_count: int
    not_assessed_count: int
    strict_readiness_pct: float
    weighted_readiness_pct: float
    gap_count: int
    formula_explanation: str
    scope_definition: str
