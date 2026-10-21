from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.models.enums import ImplementationStatus, TestingFrequency, MappingApprovalStatus


class MappedRequirementSummary(BaseModel):
    """
    Summary of a framework requirement mapped to a control.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    framework_code: str
    framework_name: str
    identifier: str
    title: str
    category: str
    approval_status: MappingApprovalStatus
    mapping_rationale: str


class ControlBase(BaseModel):
    control_id: str = Field(..., min_length=2, max_length=50, description="Identifier, e.g. CTL-IAM-01")
    name: str = Field(..., min_length=3, max_length=255, description="Control title")
    description: str = Field(..., min_length=10, description="Detailed control description")
    implementation_status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED
    testing_frequency: TestingFrequency = TestingFrequency.ANNUALLY
    evidence_requirements: str = Field(..., min_length=5, description="Audit evidence required to verify control")
    owner_id: Optional[int] = None


class ControlCreate(ControlBase):
    pass


class ControlUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = Field(None, min_length=10)
    implementation_status: Optional[ImplementationStatus] = None
    testing_frequency: Optional[TestingFrequency] = None
    evidence_requirements: Optional[str] = Field(None, min_length=5)
    owner_id: Optional[int] = None


class ControlResponse(ControlBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    last_tested_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    mapped_requirements: List[MappedRequirementSummary] = []
