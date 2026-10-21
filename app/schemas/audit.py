from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.models.enums import TestResult, FindingSeverity, FindingStatus, ActionStatus


class AuditProjectCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255, description="Audit campaign name")
    framework_id: int = Field(..., description="Target Framework ID")
    audit_type: str = Field(default="INTERNAL_READINESS", max_length=100)
    period_start: datetime
    period_end: datetime
    lead_auditor_id: Optional[int] = None
    status: str = Field(default="IN_PROGRESS", max_length=50)


class AuditProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    name: str
    framework_id: int
    framework_code: str
    framework_name: str
    audit_type: str
    period_start: datetime
    period_end: datetime
    lead_auditor_id: Optional[int] = None
    lead_auditor_name: Optional[str] = None
    status: str
    tests_count: int = 0
    created_at: datetime


class ControlTestCreate(BaseModel):
    audit_project_id: Optional[int] = None
    control_id: int = Field(..., description="SecurityControl database ID")
    test_title: str = Field(..., min_length=3, max_length=255)
    test_objective: str = Field(..., min_length=5)
    test_procedure: str = Field(..., min_length=5)
    result: TestResult = TestResult.PENDING
    sample_size: int = Field(default=0, ge=0)
    exceptions_identified: int = Field(default=0, ge=0)
    evidence_id: Optional[int] = None
    notes: Optional[str] = None


class ControlTestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    audit_project_id: Optional[int] = None
    audit_project_name: Optional[str] = None
    control_id: int
    control_code: str
    control_name: str
    test_title: str
    test_objective: str
    test_procedure: str
    result: TestResult
    tested_by_id: Optional[int] = None
    tested_by_name: Optional[str] = None
    tested_at: Optional[datetime] = None
    sample_size: int
    exceptions_identified: int
    evidence_id: Optional[int] = None
    evidence_file_name: Optional[str] = None
    evidence_hash: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
