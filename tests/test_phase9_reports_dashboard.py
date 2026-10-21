import pytest
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter


@pytest.fixture(autouse=True)
def clean_test_environment(client):
    """Ensure test client cookies and rate limiter are cleaned."""
    login_rate_limiter.reset()
    client.cookies.clear()
    yield
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


def test_api_readiness_metrics(client):
    """
    Ensure GET /api/v1/reports/readiness returns aggregated compliance posture,
    framework readiness scores, risk reduction, and regulatory disclaimer.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/reports/readiness", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert data["organization_name"] == "ApexCloud Technologies Inc."
    assert "soc2_readiness_pct" in data
    assert "iso27001_readiness_pct" in data
    assert "nist_csf_readiness_pct" in data
    assert "risk_reduction_pct" in data
    assert data["risk_reduction_pct"] > 0

    assert "frameworks" in data
    assert len(data["frameworks"]) >= 3
    fw_codes = [f["code"] for f in data["frameworks"]]
    assert "SOC2" in fw_codes
    assert "ISO27001" in fw_codes
    assert "NIST_CSF" in fw_codes

    assert "controls" in data
    assert data["controls"]["total"] >= 9
    assert data["controls"]["evidence_coverage_pct"] >= 0

    assert "tests" in data
    assert data["tests"]["total"] >= 1

    assert "findings" in data
    assert data["findings"]["total"] >= 1

    # Verify prominent legal/governance boundary declaration
    assert "regulatory_disclaimer" in data
    assert "internal readiness assessment" in data["regulatory_disclaimer"]
    assert "CPA firm" in data["regulatory_disclaimer"]
    assert "voluntary guidance" in data["regulatory_disclaimer"]


def test_api_export_markdown_report(client):
    """
    Ensure GET /api/v1/reports/export generates downloadable Markdown audit package.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/reports/export", headers=headers)
    assert response.status_code == 200
    assert "attachment" in response.headers.get("content-disposition", "")
    assert "text/markdown" in response.headers.get("content-type", "")

    content = response.text
    assert "# Executive Cybersecurity Compliance & Audit Readiness Report" in content
    assert "ApexCloud Technologies Inc." in content
    assert "SOC 2 Type II Readiness" in content
    assert "ISO/IEC 27001:2022 Readiness" in content
    assert "NIST CSF 2.0 Maturity Profile" in content
    assert "Independent Assurance & Legal Boundary Notice" in content


def test_web_ui_dashboard_page(client):
    """
    Ensure web UI /dashboard renders executive summary with framework gauges and risk posture.
    """
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "Executive Compliance &amp; Readiness Dashboard" in response.text or "Executive Compliance & Readiness Dashboard" in response.text
    assert "ApexCloud Technologies Inc." in response.text
    assert "SOC 2 Type II Readiness" in response.text
    assert "ISO 27001:2022 ISMS" in response.text
    assert "NIST CSF 2.0 Profile" in response.text
    assert "Enterprise Risk Reduction" in response.text
    assert "Evidence Vault Coverage" in response.text
    assert "Download Audit Report (.md)" in response.text


def test_web_ui_executive_report_printable(client):
    """
    Ensure web UI /reports/executive renders print-ready executive readiness report.
    """
    response = client.get("/reports/executive")
    assert response.status_code == 200
    assert "Cybersecurity Compliance Readiness Report" in response.text
    assert "Multi-Framework Operational Gap &amp; Risk Assessment" in response.text or "Multi-Framework Operational Gap & Risk Assessment" in response.text
    assert "ApexCloud Technologies Inc." in response.text
    assert "Independent External Assurance &amp; Legal Boundary Notice" in response.text or "Independent External Assurance & Legal Boundary Notice" in response.text
    assert "Chief Information Security Officer (CISO)" in response.text
    assert "Lead Internal Auditor / Compliance Officer" in response.text
