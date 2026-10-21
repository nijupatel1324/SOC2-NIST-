from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.models.enums import FindingSeverity, FindingStatus, ActionStatus


class CorrectiveActionCreate(BaseModel):
    action_plan: str = Field(..., min_length=5, description="Detailed remediation steps to correct the deficiency")
    owner_id: Optional[int] = Field(None, description="User assigned to execute the corrective action")
    target_completion_date: Optional[datetime] = None
    notes: Optional[str] = None


class CorrectiveActionUpdate(BaseModel):
    action_plan: Optional[str] = None
    owner_id: Optional[int] = None
    target_completion_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None
    status: Optional[ActionStatus] = None
    notes: Optional[str] = None


class CorrectiveActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    finding_id: int
    action_plan: str
    owner_id: Optional[int] = None
    owner_name: Optional[str] = None
    target_completion_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None
    status: ActionStatus
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class FindingCreate(BaseModel):
    control_id: int = Field(..., description="Target SecurityControl ID")
    control_test_id: Optional[int] = Field(None, description="Optional linked ControlTest ID")
    finding_id: str = Field(..., min_length=3, max_length=50, description="e.g. FND-2026-002")
    title: str = Field(..., min_length=5, max_length=255)
    severity: FindingSeverity = Field(default=FindingSeverity.MEDIUM)
    root_cause: str = Field(..., min_length=10, description="Comprehensive root-cause analysis")
    business_impact: str = Field(..., min_length=10, description="Audit and operational impact")
    owner_id: Optional[int] = None
    due_date: Optional[datetime] = None


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[FindingSeverity] = None
    root_cause: Optional[str] = None
    business_impact: Optional[str] = None
    owner_id: Optional[int] = None
    due_date: Optional[datetime] = None
    status: Optional[FindingStatus] = None


class FindingCloseRequest(BaseModel):
    closure_notes: str = Field(..., min_length=10, description="Auditor verification statement confirming remediation")
    resolution_status: FindingStatus = Field(default=FindingStatus.CLOSED, description="CLOSED or RISK_ACCEPTED")


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    finding_id: str
    title: str
    severity: FindingSeverity
    status: FindingStatus
    control_id: int
    control_code: Optional[str] = None
    control_name: Optional[str] = None
    control_test_id: Optional[int] = None
    test_title: Optional[str] = None
    root_cause: str
    business_impact: str
    owner_id: Optional[int] = None
    owner_name: Optional[str] = None
    due_date: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    closed_by_id: Optional[int] = None
    closed_by_name: Optional[str] = None
    action_count: int = 0
    created_at: datetime
    updated_at: datetime


class FindingDetailResponse(FindingResponse):
    corrective_actions: List[CorrectiveActionResponse] = []
