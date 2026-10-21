from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.enums import UserRole


class User(Base):
    """
    User entity with Role-Based Access Control (RBAC) and Organization tenancy.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(150), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.GRC_ANALYST, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="users")
    owned_controls = relationship("SecurityControl", back_populates="owner", foreign_keys="SecurityControl.owner_id")
    owned_risks = relationship("RiskAssessment", back_populates="owner", foreign_keys="RiskAssessment.owner_id")
    uploaded_evidence = relationship("EvidenceRecord", back_populates="uploaded_by", foreign_keys="EvidenceRecord.uploaded_by_id")
    conducted_tests = relationship("ControlTest", back_populates="tested_by", foreign_keys="ControlTest.tested_by_id")
    assigned_findings = relationship("AuditFinding", back_populates="owner", foreign_keys="AuditFinding.owner_id")
    assigned_actions = relationship("CorrectiveAction", back_populates="owner", foreign_keys="CorrectiveAction.owner_id")

    def __repr__(self):
        return f"<User id={self.id} email='{self.email}' role='{self.role}'>"
