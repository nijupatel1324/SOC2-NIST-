from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from app.db.session import Base


class Framework(Base):
    """
    Cybersecurity compliance standard metadata (SOC 2, ISO/IEC 27001, NIST CSF).
    """
    __tablename__ = "frameworks"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    version = Column(String(50), nullable=False)
    issuing_body = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    is_certification = Column(Boolean, default=False, nullable=False)
    assurance_type = Column(String(150), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    requirements = relationship("FrameworkRequirement", back_populates="framework", cascade="all, delete-orphan")
    audit_projects = relationship("AuditProject", back_populates="framework")

    def __repr__(self):
        return f"<Framework code='{self.code}' version='{self.version}'>"


class FrameworkRequirement(Base):
    """
    Specific requirement, clause, or control objective within a framework
    (e.g., SOC 2 CC6.1, ISO 27001 A.8.5, NIST CSF 2.0 PR.AA-01).
    """
    __tablename__ = "framework_requirements"
    __table_args__ = (
        UniqueConstraint("framework_id", "identifier", name="uq_framework_requirement_identifier"),
    )

    id = Column(Integer, primary_key=True, index=True)
    framework_id = Column(Integer, ForeignKey("frameworks.id", ondelete="CASCADE"), nullable=False, index=True)
    identifier = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(150), nullable=False)
    subcategory = Column(String(150), nullable=True)
    description = Column(Text, nullable=False)
    guidance = Column(Text, nullable=True)

    # Relationships
    framework = relationship("Framework", back_populates="requirements")
    mappings = relationship("ControlMapping", back_populates="requirement", cascade="all, delete-orphan")
    assessments = relationship("ComplianceAssessment", back_populates="requirement", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<FrameworkRequirement identifier='{self.identifier}' framework_id={self.framework_id}>"
