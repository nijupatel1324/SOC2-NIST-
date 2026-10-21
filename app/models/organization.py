from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from app.db.session import Base


class Organization(Base):
    """
    Tenant entity that enforces complete logical data isolation.
    Every compliance control, risk, evidence file, and finding belongs to an organization.
    """
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    industry = Column(String(150), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    controls = relationship("SecurityControl", back_populates="organization", cascade="all, delete-orphan")
    mappings = relationship("ControlMapping", back_populates="organization", cascade="all, delete-orphan")
    assessments = relationship("ComplianceAssessment", back_populates="organization", cascade="all, delete-orphan")
    risks = relationship("RiskAssessment", back_populates="organization", cascade="all, delete-orphan")
    evidence_records = relationship("EvidenceRecord", back_populates="organization", cascade="all, delete-orphan")
    audit_projects = relationship("AuditProject", back_populates="organization", cascade="all, delete-orphan")
    control_tests = relationship("ControlTest", back_populates="organization", cascade="all, delete-orphan")
    findings = relationship("AuditFinding", back_populates="organization", cascade="all, delete-orphan")
    corrective_actions = relationship("CorrectiveAction", back_populates="organization", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organization id={self.id} slug='{self.slug}'>"
