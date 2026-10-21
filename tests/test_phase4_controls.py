import pytest
from app.core.config import settings
from app.models.enums import ImplementationStatus, TestingFrequency


@pytest.fixture(autouse=True)
def clean_cookies(client):
    """Ensure test client cookies are cleared before and after each test."""
    client.cookies.clear()
    yield
    client.cookies.clear()


def get_token(client, email="analyst@apexcloud.io"):
    """Helper to authenticate and return a valid access token."""
    res = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": "Password123!"}
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def test_frameworks_comparison_api(client):
    """
    Ensure GET /api/v1/frameworks/comparison returns deep comparative intelligence.
    """
    response = client.get(f"{settings.API_V1_STR}/frameworks/comparison")
    assert response.status_code == 200
    data = response.json()
    assert "dimensions" in data
    assert "framework_details" in data
    assert "overlaps" in data
    assert "key_differences" in data

    # Verify specific framework details
    details = data["framework_details"]
    assert "soc2" in details
    assert "iso27001" in details
    assert "nist_csf" in details
    assert "Voluntary" in details["nist_csf"]["type"]


def test_frameworks_requirements_api(client):
    """
    Ensure GET /api/v1/frameworks/requirements returns catalog and respects filters.
    """
    # 1. All requirements
    res_all = client.get(f"{settings.API_V1_STR}/frameworks/requirements")
    assert res_all.status_code == 200
    all_reqs = res_all.json()
    assert len(all_reqs) >= 30

    # 2. Filter by SOC 2
    res_soc2 = client.get(f"{settings.API_V1_STR}/frameworks/requirements?framework_code=SOC2")
    assert res_soc2.status_code == 200
    soc2_reqs = res_soc2.json()
    assert all(r["framework_code"] == "SOC2" for r in soc2_reqs)
    identifiers = [r["identifier"] for r in soc2_reqs]
    assert "CC6.1" in identifiers


def test_web_frameworks_page(client):
    """
    Ensure GET /frameworks renders interactive HTML comparison view.
    """
    response = client.get("/frameworks")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    body = response.text
    assert "SOC 2 vs ISO/IEC 27001:2022 vs NIST CSF 2.0" in body
    assert "Multi-Dimensional Comparison Matrix" in body
    assert "Critical Areas of Framework Overlap" in body


def test_list_controls_api(client):
    """
    Ensure GET /api/v1/controls returns controls with mapped framework references.
    """
    token = get_token(client, email="analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/controls", headers=headers)
    assert response.status_code == 200
    controls = response.json()
    assert len(controls) >= 9

    # Verify CTL-IAM-01 has mapped requirements
    iam_control = next((c for c in controls if c["control_id"] == "CTL-IAM-01"), None)
    assert iam_control is not None
    assert iam_control["name"] == "Multi-Factor Authentication (MFA) for Administrative & Cloud Console Access"
    assert len(iam_control["mapped_requirements"]) >= 3
    mapped_codes = {m["framework_code"] for m in iam_control["mapped_requirements"]}
    assert "SOC2" in mapped_codes
    assert "ISO27001" in mapped_codes
    assert "NIST_CSF" in mapped_codes


def test_create_control_lifecycle(client):
    """
    Validate full lifecycle of creating, updating, and deleting a control.
    """
    analyst_token = get_token(client, email="analyst@apexcloud.io")
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. GRC Analyst creates a new control
    new_control_payload = {
        "control_id": "CTL-SIEM-99",
        "name": "Automated Threat Intelligence Ingestion",
        "description": "Ingestion of open-source and commercial threat intelligence IOCs into SIEM daily.",
        "implementation_status": "IMPLEMENTED",
        "testing_frequency": "CONTINUOUS",
        "evidence_requirements": "Threat intel API logs and correlation alert configuration."
    }
    create_res = client.post(
        f"{settings.API_V1_STR}/controls",
        json=new_control_payload,
        headers=analyst_headers
    )
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["control_id"] == "CTL-SIEM-99"

    # 2. Duplicate control_id is rejected with 400
    dup_res = client.post(
        f"{settings.API_V1_STR}/controls",
        json=new_control_payload,
        headers=analyst_headers
    )
    assert dup_res.status_code == 400
    assert "already exists" in dup_res.json()["detail"]

    # 3. Org Admin updates the control
    admin_token = get_token(client, email="security.lead@apexcloud.io")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    update_payload = {
        "description": "Updated: Ingestion of commercial and CISA AIS threat feeds with automated blocking."
    }
    update_res = client.put(
        f"{settings.API_V1_STR}/controls/CTL-SIEM-99",
        json=update_payload,
        headers=admin_headers
    )
    assert update_res.status_code == 200
    assert "CISA AIS" in update_res.json()["description"]

    # 4. GRC Analyst tries to delete -> 403 Forbidden (Admin only)
    analyst_del_res = client.delete(
        f"{settings.API_V1_STR}/controls/CTL-SIEM-99",
        headers=analyst_headers
    )
    assert analyst_del_res.status_code == 403

    # 5. Org Admin deletes the control -> 204 No Content
    del_res = client.delete(
        f"{settings.API_V1_STR}/controls/CTL-SIEM-99",
        headers=admin_headers
    )
    assert del_res.status_code == 204

    # 6. Verify deleted
    get_res = client.get(
        f"{settings.API_V1_STR}/controls/CTL-SIEM-99",
        headers=admin_headers
    )
    assert get_res.status_code == 404


def test_auditor_cannot_create_controls(client):
    """
    Ensure read-only auditor role is forbidden from creating controls.
    """
    auditor_token = get_token(client, email="auditor@cpa-assurance.com")
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    payload = {
        "control_id": "CTL-AUDIT-01",
        "name": "Auditor Created Control",
        "description": "This should be blocked by RBAC.",
        "evidence_requirements": "N/A"
    }
    response = client.post(
        f"{settings.API_V1_STR}/controls",
        json=payload,
        headers=auditor_headers
    )
    assert response.status_code == 403
    assert "Access forbidden" in response.json()["detail"]


def test_web_controls_views(client):
    """
    Ensure web browser views for /controls and /controls/{control_id} render properly.
    """
    # 1. Catalog list page
    list_res = client.get("/controls")
    assert list_res.status_code == 200
    assert "Organizational Security Controls" in list_res.text
    assert "CTL-IAM-01" in list_res.text
    assert "CTL-CRY-01" in list_res.text

    # 2. Control detail page
    detail_res = client.get("/controls/CTL-IAM-01")
    assert detail_res.status_code == 200
    assert "Multi-Factor Authentication" in detail_res.text
    assert "Cross-Framework Mappings" in detail_res.text
    assert "SOC 2" in detail_res.text
    assert "ISO/IEC 27001:2022" in detail_res.text
    assert "NIST CSF 2.0" in detail_res.text
