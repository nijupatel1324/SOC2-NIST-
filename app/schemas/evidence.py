from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.models.enums import EvidenceReviewStatus


class EvidenceReviewRequest(BaseModel):
    status: EvidenceReviewStatus = Field(..., description="APPROVED, REJECTED, or EXPIRED")
    review_notes: Optional[str] = None


class EvidenceIntegrityCheck(BaseModel):
    evidence_id: int
    file_name: str
    database_hash: str
    calculated_hash: str
    is_valid: bool
    status: str
    verified_at: datetime


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    control_id: Optional[int] = None
    control_code: Optional[str] = None
    control_name: Optional[str] = None
    title: str
    description: str
    file_name: str
    file_size_bytes: int
    mime_type: str
    sha256_hash: str
    uploaded_by_id: Optional[int] = None
    uploaded_by_name: Optional[str] = None
    review_status: EvidenceReviewStatus
    reviewed_by_id: Optional[int] = None
    reviewed_by_name: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    retention_date: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
