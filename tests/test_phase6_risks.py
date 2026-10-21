import pytest
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter
from app.models.enums import RiskLevel, RiskTreatmentStrategy, RiskStatus


@pytest.fixture(autouse=True)
def clean_cookies(client):
    """Ensure test client cookies, rate limiter, and test risk records are clean."""
    from app.db.session import SessionLocal
    from app.models import RiskAssessment

    def cleanup_test_risks():
        db = SessionLocal()
        try:
            test_ids = ["RSK-TEST-999", "RSK-TEMP-001", "RSK-ACCEPT-TEST"]
            db.query(RiskAssessment).filter(RiskAssessment.risk_id.in_(test_ids)).delete(synchronize_session=False)
            db.commit()
        finally:
            db.close()

    cleanup_test_risks()
    login_rate_limiter.reset()
    client.cookies.clear()
    yield
    cleanup_test_risks()
    login_rate_limiter.reset()
    client.cookies.clear()


def get_token(client, email="analyst@apexcloud.io"):
    """Helper to authenticate and return a valid access token."""
    res = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": "Password123!"}
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def test_list_risks(client):
    """
    Ensure GET /api/v1/risks lists cybersecurity risks for the organization.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/risks", headers=headers)
    assert response.status_code == 200
    risks = response.json()
    assert isinstance(risks, list)
    assert len(risks) >= 3

    # Verify demonstration scenario presence
    mfa_risk = next((r for r in risks if r["risk_id"] == "RSK-2026-001"), None)
    assert mfa_risk is not None
    assert "Missing MFA" in mfa_risk["title"]
    assert mfa_risk["inherent_score"] == 20
    assert mfa_risk["inherent_level"] == "CRITICAL"
    assert mfa_risk["residual_score"] == 4
    assert mfa_risk["residual_level"] == "LOW"


def test_risk_filtering(client):
    """
    Ensure GET /api/v1/risks supports filtering by level, status, and strategy.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Filter by CRITICAL inherent risk
    res_crit = client.get(f"{settings.API_V1_STR}/risks?level=CRITICAL", headers=headers)
    assert res_crit.status_code == 200
    crit_risks = res_crit.json()
    assert len(crit_risks) >= 1
    assert all(r["inherent_level"] == "CRITICAL" for r in crit_risks)

    # 2. Filter by MITIGATE strategy
    res_mit = client.get(f"{settings.API_V1_STR}/risks?strategy=MITIGATE", headers=headers)
    assert res_mit.status_code == 200
    assert all(r["treatment_strategy"] == "MITIGATE" for r in res_mit.json())


def test_get_single_risk_details(client):
    """
    Ensure GET /api/v1/risks/{risk_id} returns comprehensive threat profile.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/risks/RSK-2026-001", headers=headers)
    assert response.status_code == 200
    risk = response.json()
    assert risk["risk_id"] == "RSK-2026-001"
    assert "AWS Production" in risk["affected_asset"]
    assert "Credential Stuffing" in risk["threat_source"]
    assert risk["inherent_likelihood"] == 4
    assert risk["inherent_impact"] == 5
    assert risk["inherent_score"] == 20


def test_create_risk_success_and_score_calculation(client):
    """
    Ensure creating a new risk auto-computes 5x5 matrix scores and levels.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "risk_id": "RSK-TEST-999",
        "title": "Unauthenticated S3 Bucket with Public Write Access",
        "affected_asset": "Customer Document Storage S3 Bucket",
        "threat_source": "Automated Internet Scanners / External Attackers",
        "vulnerability": "Bucket ACL misconfiguration allowing anonymous read/write",
        "business_impact": "Total data breach and malware hosting on corporate domain",
        "inherent_likelihood": 3,
        "inherent_impact": 5,  # Score: 3x5 = 15 (HIGH)
        "existing_safeguards": "AWS GuardDuty basic alerts",
        "residual_likelihood": 1,
        "residual_impact": 2,  # Score: 1x2 = 2 (LOW)
        "treatment_strategy": "MITIGATE",
        "treatment_details": "Enforce AWS Organizations SCP blocking all public S3 buckets.",
        "status": "IN_TREATMENT"
    }

    create_res = client.post(f"{settings.API_V1_STR}/risks", json=payload, headers=headers)
    assert create_res.status_code == 201
    data = create_res.json()
    assert data["risk_id"] == "RSK-TEST-999"
    assert data["inherent_score"] == 15
    assert data["inherent_level"] == "HIGH"
    assert data["residual_score"] == 2
    assert data["residual_level"] == "LOW"

    # Cleanup test risk
    del_res = client.delete(f"{settings.API_V1_STR}/risks/RSK-TEST-999", headers=headers)
    assert del_res.status_code == 204


def test_create_risk_duplicate_rejected(client):
    """
    Ensure creating a risk with duplicate risk_id is rejected with 400 Bad Request.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "risk_id": "RSK-2026-001",  # Already seeded
        "title": "Duplicate MFA Risk",
        "affected_asset": "AWS IAM",
        "threat_source": "Attackers",
        "vulnerability": "Missing MFA",
        "business_impact": "Data compromise",
        "inherent_likelihood": 4,
        "inherent_impact": 5,
        "residual_likelihood": 2,
        "residual_impact": 2,
        "treatment_strategy": "MITIGATE",
        "treatment_details": "Enforce MFA",
        "status": "IDENTIFIED"
    }

    response = client.post(f"{settings.API_V1_STR}/risks", json=payload, headers=headers)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"].lower()


def test_update_risk_and_score_recalculation(client):
    """
    Ensure updating risk likelihood or impact automatically recalculates scores and levels.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # Create temporary risk
    create_res = client.post(
        f"{settings.API_V1_STR}/risks",
        json={
            "risk_id": "RSK-TEMP-001",
            "title": "Temporary Test Risk",
            "affected_asset": "Dev Environment",
            "threat_source": "Script Kiddies",
            "vulnerability": "Open port 22",
            "business_impact": "Dev machine compromise",
            "inherent_likelihood": 2,
            "inherent_impact": 3,  # Score: 6 (MEDIUM)
            "residual_likelihood": 1,
            "residual_impact": 1,  # Score: 1 (LOW)
            "treatment_strategy": "MITIGATE",
            "treatment_details": "Close SSH port",
            "status": "IDENTIFIED"
        },
        headers=headers
    )
    assert create_res.status_code == 201

    # Update inherent impact to 5 -> Inherent score becomes 2 * 5 = 10 (MEDIUM)
    # Then likelihood to 4 -> Inherent score becomes 4 * 5 = 20 (CRITICAL)
    upd_res = client.put(
        f"{settings.API_V1_STR}/risks/RSK-TEMP-001",
        json={"inherent_likelihood": 4, "inherent_impact": 5},
        headers=headers
    )
    assert upd_res.status_code == 200
    upd_data = upd_res.json()
    assert upd_data["inherent_score"] == 20
    assert upd_data["inherent_level"] == "CRITICAL"

    # Cleanup
    client.delete(f"{settings.API_V1_STR}/risks/RSK-TEMP-001", headers=headers)


def test_risk_acceptance_sign_off_workflow(client):
    """
    Ensure formal executive risk acceptance requires justification,
    updates risk status to ACCEPTED, and records the authorizer identity.
    """
    analyst_token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Create risk to accept
    create_res = client.post(
        f"{settings.API_V1_STR}/risks",
        json={
            "risk_id": "RSK-ACCEPT-TEST",
            "title": "Legacy VPN Incompatible with Modern SAML MFA",
            "affected_asset": "Branch Office Legacy VPN Gateway",
            "threat_source": "Credential Harvesting",
            "vulnerability": "Legacy protocol only supports RADIUS credentials",
            "business_impact": "Localized breach of branch office network",
            "inherent_likelihood": 3,
            "inherent_impact": 3,
            "residual_likelihood": 2,
            "residual_impact": 2,
            "treatment_strategy": "ACCEPT",
            "treatment_details": "Decommission scheduled in Q4 2026; compensating IP allowlist in place.",
            "status": "IDENTIFIED"
        },
        headers=headers
    )
    assert create_res.status_code == 201

    # Formally sign-off on risk acceptance
    accept_payload = {
        "rationale": "Hardware gateway scheduled for replacement in Q4; compensated by strict source IP whitelisting."
    }
    accept_res = client.post(
        f"{settings.API_V1_STR}/risks/RSK-ACCEPT-TEST/accept",
        json=accept_payload,
        headers=headers
    )
    assert accept_res.status_code == 200
    acc_data = accept_res.json()
    assert acc_data["status"] == "ACCEPTED"
    assert acc_data["treatment_strategy"] == "ACCEPT"
    assert acc_data["risk_accepted_by_name"] is not None
    assert acc_data["risk_accepted_at"] is not None
    assert "compensated by strict source IP" in acc_data["risk_acceptance_rationale"]

    # Cleanup
    client.delete(f"{settings.API_V1_STR}/risks/RSK-ACCEPT-TEST", headers=headers)


def test_risk_acceptance_rbac_restricted(client):
    """
    Ensure Auditor cannot formally sign off on risk acceptance (restricted to Admins / GRC Analysts).
    """
    auditor_token = get_token(client, "auditor@cpa-assurance.com")
    headers = {"Authorization": f"Bearer {auditor_token}"}

    res = client.post(
        f"{settings.API_V1_STR}/risks/RSK-2026-001/accept",
        json={"rationale": "Unauthorized auditor acceptance"},
        headers=headers
    )
    assert res.status_code == 403


def test_risk_matrix_summary_endpoint(client):
    """
    Ensure GET /api/v1/risks/matrix returns 25 matrix cells and exposure reduction.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/risks/matrix", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "matrix" in data
    assert len(data["matrix"]) == 25  # 5x5 cells
    assert data["total_risks"] >= 3
    assert data["average_inherent_score"] > 0
    assert data["average_residual_score"] < data["average_inherent_score"]
    assert data["risk_reduction_pct"] > 0.0


def test_web_risk_views(client):
    """
    Ensure HTML templates for Risk Register and Risk Detail views render correctly.
    """
    # 1. Risk Register Dashboard
    res_dash = client.get("/risks")
    assert res_dash.status_code == 200
    assert "text/html" in res_dash.headers["content-type"]
    assert "Enterprise Cybersecurity Risk Register" in res_dash.text
    assert "5&times;5 Likelihood &times; Impact Risk Matrix" in res_dash.text
    assert "RSK-2026-001" in res_dash.text

    # 2. Risk Detail View
    res_detail = client.get("/risks/RSK-2026-001")
    assert res_detail.status_code == 200
    assert "text/html" in res_detail.headers["content-type"]
    assert "Threat & Vulnerability Profile" in res_detail.text
    assert "Inherent Risk (Pre-Mitigation)" in res_detail.text
    assert "Residual Risk (Post-Mitigation)" in res_detail.text
