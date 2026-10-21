from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.enums import EvidenceReviewStatus


class EvidenceRecord(Base):
    """
    Audit evidence document metadata and cryptographic fingerprint.
    Stored securely in private file storage; integrity verified via SHA-256.
    """
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(Integer, ForeignKey("security_controls.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    file_name = Column(String(255), nullable=False)
    stored_file_path = Column(String(500), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)

    uploaded_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    review_status = Column(
        SQLEnum(EvidenceReviewStatus),
        default=EvidenceReviewStatus.PENDING_REVIEW,
        nullable=False
    )
    reviewed_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    retention_date = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="evidence_records")
    control = relationship("SecurityControl", back_populates="evidence_records")
    uploaded_by = relationship("User", back_populates="uploaded_evidence", foreign_keys=[uploaded_by_id])
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
    tests = relationship("ControlTest", back_populates="evidence")

    def __repr__(self):
        return f"<EvidenceRecord id={self.id} file='{self.file_name}' hash='{self.sha256_hash[:8]}...'>"
