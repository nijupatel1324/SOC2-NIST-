from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum as SQLEnum, UniqueConstraint
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.enums import ImplementationStatus, TestingFrequency, MappingApprovalStatus, AssessmentStatus


class SecurityControl(Base):
    """
    Centralized internal cybersecurity control catalog.
    Maintained by an organization and mapped to multiple framework requirements.
    """
    __tablename__ = "security_controls"
    __table_args__ = (
        UniqueConstraint("organization_id", "control_id", name="uq_org_control_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(50), nullable=False, index=True)  # e.g., CTL-IAM-01
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    implementation_status = Column(
        SQLEnum(ImplementationStatus),
        default=ImplementationStatus.NOT_IMPLEMENTED,
        nullable=False
    )
    testing_frequency = Column(
        SQLEnum(TestingFrequency),
        default=TestingFrequency.ANNUALLY,
        nullable=False
    )
    evidence_requirements = Column(Text, nullable=False)
    last_tested_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="controls")
    owner = relationship("User", back_populates="owned_controls", foreign_keys=[owner_id])
    mappings = relationship("ControlMapping", back_populates="control", cascade="all, delete-orphan")
    evidence_records = relationship("EvidenceRecord", back_populates="control")
    tests = relationship("ControlTest", back_populates="control", cascade="all, delete-orphan")
    findings = relationship("AuditFinding", back_populates="control", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<SecurityControl control_id='{self.control_id}' org_id={self.organization_id}>"


class ControlMapping(Base):
    """
    Proposed or approved relationship linking an internal control to a specific
    requirement in SOC 2, ISO 27001, or NIST CSF.
    """
    __tablename__ = "control_mappings"
    __table_args__ = (
        UniqueConstraint("organization_id", "control_id", "requirement_id", name="uq_control_requirement_mapping"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(Integer, ForeignKey("security_controls.id", ondelete="CASCADE"), nullable=False, index=True)
    requirement_id = Column(Integer, ForeignKey("framework_requirements.id", ondelete="CASCADE"), nullable=False, index=True)
    mapping_rationale = Column(Text, nullable=False)
    approval_status = Column(
        SQLEnum(MappingApprovalStatus),
        default=MappingApprovalStatus.PROPOSED,
        nullable=False
    )
    reviewed_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="mappings")
    control = relationship("SecurityControl", back_populates="mappings")
    requirement = relationship("FrameworkRequirement", back_populates="mappings")
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])

    def __repr__(self):
        return f"<ControlMapping control={self.control_id} requirement={self.requirement_id} status='{self.approval_status}'>"


class ComplianceAssessment(Base):
    """
    Assesses an organization's implementation readiness against a specific framework requirement.
    Includes gap identification, justifications, and remediation steps.
    """
    __tablename__ = "compliance_assessments"
    __table_args__ = (
        UniqueConstraint("organization_id", "requirement_id", name="uq_org_requirement_assessment"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    requirement_id = Column(Integer, ForeignKey("framework_requirements.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(
        SQLEnum(AssessmentStatus),
        default=AssessmentStatus.NOT_ASSESSED,
        nullable=False
    )
    justification = Column(Text, nullable=True)
    assessed_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    identified_gaps = Column(Text, nullable=True)
    recommended_actions = Column(Text, nullable=True)
    assessed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="assessments")
    requirement = relationship("FrameworkRequirement", back_populates="assessments")
    assessed_by = relationship("User", foreign_keys=[assessed_by_id])

    def __repr__(self):
        return f"<ComplianceAssessment requirement_id={self.requirement_id} status='{self.status}'>"
