from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.models.enums import MappingApprovalStatus


class MappingBase(BaseModel):
    control_id: int = Field(..., description="Internal SecurityControl database ID")
    requirement_id: int = Field(..., description="FrameworkRequirement database ID")
    mapping_rationale: str = Field(
        ...,
        min_length=5,
        description="Technical justification for how this control satisfies the requirement"
    )


class MappingCreate(MappingBase):
    approval_status: Optional[MappingApprovalStatus] = MappingApprovalStatus.PROPOSED


class MappingUpdate(BaseModel):
    mapping_rationale: Optional[str] = Field(None, min_length=5)
    approval_status: Optional[MappingApprovalStatus] = None


class MappingReview(BaseModel):
    approval_status: MappingApprovalStatus = Field(..., description="APPROVED, REJECTED, or UNDER_REVIEW")
    review_comment: Optional[str] = None


class MappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    control_id: int
    control_code: str
    control_name: str
    control_status: str
    requirement_id: int
    framework_code: str
    framework_name: str
    requirement_identifier: str
    requirement_title: str
    requirement_category: str
    mapping_rationale: str
    approval_status: MappingApprovalStatus
    reviewed_by_id: Optional[int] = None
    reviewed_by_name: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime


class CrossFrameworkMatrixRow(BaseModel):
    """
    Representation of an internal control and its cross-mapped requirements
    across SOC 2, ISO/IEC 27001, and NIST CSF 2.0.
    """
    control_id: str
    control_name: str
    control_status: str
    soc2_mappings: List[str]
    iso27001_mappings: List[str]
    nist_csf_mappings: List[str]
    total_mappings: int
