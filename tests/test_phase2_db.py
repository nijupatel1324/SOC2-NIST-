import hashlib
from pathlib import Path
import pytest
from app.db.session import SessionLocal
from app.core.security import verify_password
from app.models import (
    Organization,
    User,
    UserRole,
    Framework,
    FrameworkRequirement,
    SecurityControl,
    ControlMapping,
    ComplianceAssessment,
    RiskAssessment,
    EvidenceRecord,
    AuditProject,
    ControlTest,
    AuditFinding,
    CorrectiveAction,
    AuditEvent,
    TestResult,
    FindingSeverity,
    FindingStatus,
    ActionStatus,
    RiskLevel
)


@pytest.fixture(scope="module")
def db():
    """
    Database session fixture for Phase 2 integration tests.
    """
    session = SessionLocal()
    yield session
    session.close()


def test_organization_and_tenancy(db):
    """
    Verify organization entity and multi-tenant root.
    """
    org = db.query(Organization).filter_by(slug="apexcloud").first()
    assert org is not None
    assert org.name == "ApexCloud Technologies Inc."
    assert org.industry == "Cloud Infrastructure & Financial SaaS"
    assert len(org.controls) >= 9
    assert len(org.risks) >= 3


def test_user_roles_and_bcrypt_passwords(db):
    """
    Ensure all 5 required roles exist and passwords hash and verify securely.
    """
    roles_expected = {
        "admin@apexcloud.io": UserRole.PLATFORM_ADMIN,
        "security.lead@apexcloud.io": UserRole.ORG_ADMIN,
        "analyst@apexcloud.io": UserRole.GRC_ANALYST,
        "it.owner@apexcloud.io": UserRole.CONTROL_OWNER,
        "auditor@cpa-assurance.com": UserRole.AUDITOR,
    }

    for email, expected_role in roles_expected.items():
        user = db.query(User).filter_by(email=email).first()
        assert user is not None, f"User {email} missing"
        assert user.role == expected_role
        assert verify_password("Password123!", user.hashed_password) is True
        assert verify_password("WrongPassword!", user.hashed_password) is False


def test_frameworks_metadata(db):
    """
    Verify that SOC 2, ISO 27001, and NIST CSF 2.0 metadata adhere to regulatory reality.
    - NIST CSF must NOT be designated as certification.
    - ISO 27001 is an accredited certification.
    - SOC 2 is an attestation examination report.
    """
    soc2 = db.query(Framework).filter_by(code="SOC2").first()
    iso = db.query(Framework).filter_by(code="ISO27001").first()
    nist = db.query(Framework).filter_by(code="NIST_CSF").first()

    assert soc2 is not None
    assert iso is not None
    assert nist is not None

    # Crucial regulatory claims assertions
    assert nist.is_certification is False
    assert "Voluntary" in nist.assurance_type
    assert iso.is_certification is True
    assert "Certification" in iso.assurance_type
    assert soc2.is_certification is False
    assert "Attestation" in soc2.assurance_type


def test_cross_framework_control_mapping(db):
    """
    Validate Module C: One internal control maps to multiple framework requirements.
    CTL-IAM-01 (MFA) must map to SOC 2 (CC6.1), ISO 27001 (A.8.5), and NIST CSF (PR.AA-03).
    """
    mfa_control = db.query(SecurityControl).filter_by(control_id="CTL-IAM-01").first()
    assert mfa_control is not None
    assert len(mfa_control.mappings) >= 3

    mapped_framework_codes = {
        mapping.requirement.framework.code for mapping in mfa_control.mappings
    }
    assert "SOC2" in mapped_framework_codes
    assert "ISO27001" in mapped_framework_codes
    assert "NIST_CSF" in mapped_framework_codes

    # Verify specific identifiers
    mapped_identifiers = {mapping.requirement.identifier for mapping in mfa_control.mappings}
    assert "CC6.1" in mapped_identifiers
    assert "A.8.5" in mapped_identifiers
    assert "PR.AA-03" in mapped_identifiers


def test_risk_assessment_scoring_and_levels(db):
    """
    Validate Module D: 5x5 Likelihood x Impact scoring and inherent vs residual reduction.
    """
    mfa_risk = db.query(RiskAssessment).filter_by(risk_id="RSK-2026-001").first()
    assert mfa_risk is not None

    # Inherent risk
    assert mfa_risk.inherent_likelihood == 4
    assert mfa_risk.inherent_impact == 5
    assert mfa_risk.inherent_score == 20
    assert mfa_risk.inherent_level == RiskLevel.CRITICAL

    # Residual risk after CTL-IAM-01 treatment
    assert mfa_risk.residual_likelihood == 2
    assert mfa_risk.residual_impact == 2
    assert mfa_risk.residual_score == 4
    assert mfa_risk.residual_level == RiskLevel.LOW
    assert mfa_risk.residual_score < mfa_risk.inherent_score


def test_demonstration_scenario_lifecycle(db):
    """
    Validate Project Objective 5 Demonstration Workflow:
    1. Identify missing MFA on privileged accounts.
    2. Record risk (RSK-2026-001) with 20 Inherent -> 4 Residual.
    3. Link to SOC 2 (CC6.1), ISO 27001 (A.8.5), NIST CSF (PR.AA-03).
    4. Control test fails with 4 exceptions.
    5. Finding FND-2026-001 recorded and assigned to IT Owner.
    6. Corrective Action Plan (CAPA) assigned and in progress.
    7. Evidence file exists on disk and matches SHA-256 hash.
    """
    # 1 & 2. Risk
    risk = db.query(RiskAssessment).filter_by(risk_id="RSK-2026-001").first()
    assert risk is not None

    # 3. Control & Mappings
    control = db.query(SecurityControl).filter_by(control_id="CTL-IAM-01").first()
    assert control is not None

    # 4. Failed Test
    test = db.query(ControlTest).filter_by(control_id=control.id).first()
    assert test is not None
    assert test.result == TestResult.FAIL
    assert test.exceptions_identified == 4

    # 5. Finding
    finding = db.query(AuditFinding).filter_by(finding_id="FND-2026-001").first()
    assert finding is not None
    assert finding.severity == FindingSeverity.HIGH
    assert finding.status == FindingStatus.REMEDIATION_IN_PROGRESS

    # 6. Corrective Action
    assert len(finding.corrective_actions) >= 1
    action = finding.corrective_actions[0]
    assert action.status == ActionStatus.IN_PROGRESS
    assert action.owner.email == "it.owner@apexcloud.io"

    # 7. Evidence file cryptographic integrity
    evidence = test.evidence
    assert evidence is not None
    file_path = Path(evidence.stored_file_path)
    assert file_path.exists(), f"Evidence file {file_path} not found on disk"
    
    # Calculate file SHA-256
    file_content = file_path.read_bytes()
    computed_hash = hashlib.sha256(file_content).hexdigest()
    assert computed_hash == evidence.sha256_hash, "Evidence SHA-256 mismatch!"


def test_audit_event_trail(db):
    """
    Validate immutable audit event logging table.
    """
    events = db.query(AuditEvent).all()
    assert len(events) >= 4
    actions = {e.action for e in events}
    assert "ORGANIZATION_INITIALIZED" in actions
    assert "CONTROL_TEST_FAILED" in actions
    assert "AUDIT_FINDING_CREATED" in actions
