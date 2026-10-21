from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum as SQLEnum, UniqueConstraint
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.enums import RiskLevel, RiskTreatmentStrategy, RiskStatus


class RiskAssessment(Base):
    """
    Risk register entity.
    Calculates inherent and residual risk using a standard 5x5 Likelihood x Impact matrix.
    Tracks safeguards, treatment workflows, and risk acceptance sign-offs.
    """
    __tablename__ = "risk_assessments"
    __table_args__ = (
        UniqueConstraint("organization_id", "risk_id", name="uq_org_risk_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    risk_id = Column(String(50), nullable=False, index=True)  # e.g., RSK-2026-001
    title = Column(String(255), nullable=False)
    affected_asset = Column(String(255), nullable=False)
    threat_source = Column(String(255), nullable=False)
    vulnerability = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Inherent Risk (Before Controls)
    inherent_likelihood = Column(Integer, default=3, nullable=False)  # 1 to 5
    inherent_impact = Column(Integer, default=3, nullable=False)      # 1 to 5
    inherent_score = Column(Integer, default=9, nullable=False)       # 1 to 25
    inherent_level = Column(SQLEnum(RiskLevel), default=RiskLevel.MEDIUM, nullable=False)

    # Safeguards & Controls
    existing_safeguards = Column(Text, nullable=True)

    # Residual Risk (After Controls)
    residual_likelihood = Column(Integer, default=2, nullable=False)  # 1 to 5
    residual_impact = Column(Integer, default=2, nullable=False)      # 1 to 5
    residual_score = Column(Integer, default=4, nullable=False)       # 1 to 25
    residual_level = Column(SQLEnum(RiskLevel), default=RiskLevel.LOW, nullable=False)

    # Treatment Strategy & Formal Acceptance
    treatment_strategy = Column(
        SQLEnum(RiskTreatmentStrategy),
        default=RiskTreatmentStrategy.MITIGATE,
        nullable=False
    )
    treatment_details = Column(Text, nullable=False)
    risk_acceptance_rationale = Column(Text, nullable=True)
    risk_accepted_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    risk_accepted_at = Column(DateTime, nullable=True)

    status = Column(SQLEnum(RiskStatus), default=RiskStatus.IDENTIFIED, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="risks")
    owner = relationship("User", back_populates="owned_risks", foreign_keys=[owner_id])
    risk_accepted_by = relationship("User", foreign_keys=[risk_accepted_by_id])

    def __repr__(self):
        return f"<RiskAssessment risk_id='{self.risk_id}' score={self.inherent_score}->{self.residual_score}>"
