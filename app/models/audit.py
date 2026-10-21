from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.enums import TestResult, FindingSeverity, FindingStatus, ActionStatus


class AuditProject(Base):
    """
    Audit campaign or internal readiness review cycle
    (e.g., '2026 SOC 2 Type II Preparation', 'ISO 27001 Annual Surveillance').
    """
    __tablename__ = "audit_projects"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    framework_id = Column(Integer, ForeignKey("frameworks.id", ondelete="RESTRICT"), nullable=False)
    audit_type = Column(String(100), default="INTERNAL_READINESS", nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    lead_auditor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(50), default="IN_PROGRESS", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="audit_projects")
    framework = relationship("Framework", back_populates="audit_projects")
    lead_auditor = relationship("User", foreign_keys=[lead_auditor_id])
    tests = relationship("ControlTest", back_populates="audit_project")

    def __repr__(self):
        return f"<AuditProject name='{self.name}' status='{self.status}'>"


class ControlTest(Base):
    """
    Audit testing procedure documentation, sample sizes, exceptions, and pass/fail result.
    """
    __tablename__ = "control_tests"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    audit_project_id = Column(Integer, ForeignKey("audit_projects.id", ondelete="SET NULL"), nullable=True, index=True)
    control_id = Column(Integer, ForeignKey("security_controls.id", ondelete="CASCADE"), nullable=False, index=True)
    test_title = Column(String(255), nullable=False)
    test_objective = Column(Text, nullable=False)
    test_procedure = Column(Text, nullable=False)
    result = Column(SQLEnum(TestResult), default=TestResult.PENDING, nullable=False)
    tested_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    tested_at = Column(DateTime, nullable=True)
    sample_size = Column(Integer, default=0, nullable=False)
    exceptions_identified = Column(Integer, default=0, nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence_records.id", ondelete="SET NULL"), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="control_tests")
    audit_project = relationship("AuditProject", back_populates="tests")
    control = relationship("SecurityControl", back_populates="tests")
    tested_by = relationship("User", back_populates="conducted_tests", foreign_keys=[tested_by_id])
    evidence = relationship("EvidenceRecord", back_populates="tests")
    findings = relationship("AuditFinding", back_populates="control_test")

    def __repr__(self):
        return f"<ControlTest id={self.id} result='{self.result}'>"


class AuditFinding(Base):
    """
    Deficiency or non-conformity identified during control testing.
    Requires root-cause analysis, severity classification, and corrective action closure.
    """
    __tablename__ = "audit_findings"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    control_test_id = Column(Integer, ForeignKey("control_tests.id", ondelete="SET NULL"), nullable=True, index=True)
    control_id = Column(Integer, ForeignKey("security_controls.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(50), nullable=False, index=True)  # e.g., FND-2026-001
    title = Column(String(255), nullable=False)
    severity = Column(SQLEnum(FindingSeverity), default=FindingSeverity.MEDIUM, nullable=False)
    root_cause = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    due_date = Column(DateTime, nullable=True)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    closed_at = Column(DateTime, nullable=True)
    closed_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="findings")
    control_test = relationship("ControlTest", back_populates="findings")
    control = relationship("SecurityControl", back_populates="findings")
    owner = relationship("User", back_populates="assigned_findings", foreign_keys=[owner_id])
    closed_by = relationship("User", foreign_keys=[closed_by_id])
    corrective_actions = relationship("CorrectiveAction", back_populates="finding", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<AuditFinding finding_id='{self.finding_id}' severity='{self.severity}' status='{self.status}'>"


class CorrectiveAction(Base):
    """
    Corrective Action Plan (CAPA) tracking remediation progress to closure.
    """
    __tablename__ = "corrective_actions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("audit_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    action_plan = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    target_completion_date = Column(DateTime, nullable=True)
    actual_completion_date = Column(DateTime, nullable=True)
    status = Column(SQLEnum(ActionStatus), default=ActionStatus.OPEN, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="corrective_actions")
    finding = relationship("AuditFinding", back_populates="corrective_actions")
    owner = relationship("User", back_populates="assigned_actions", foreign_keys=[owner_id])

    def __repr__(self):
        return f"<CorrectiveAction id={self.id} finding_id={self.finding_id} status='{self.status}'>"


class AuditEvent(Base):
    """
    Append-only security audit log recording every sensitive action, change, and approval.
    """
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)  # JSON-encoded payload
    ip_address = Column(String(45), default="127.0.0.1", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    organization = relationship("Organization", back_populates="audit_events")
    user = relationship("User")

    def __repr__(self):
        return f"<AuditEvent id={self.id} action='{self.action}' resource='{self.resource_type}:{self.resource_id}'>"
