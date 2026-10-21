import pytest
from app.core.config import settings
from app.models.enums import MappingApprovalStatus, AssessmentStatus


from app.core.rate_limit import login_rate_limiter


@pytest.fixture(autouse=True)
def clean_cookies(client):
    """Ensure test client cookies and rate limiter are cleared before and after each test."""
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


def test_list_mappings(client):
    """
    Ensure GET /api/v1/mappings lists cross-framework mappings for the organization.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/mappings", headers=headers)
    assert response.status_code == 200
    mappings = response.json()
    assert isinstance(mappings, list)
    assert len(mappings) >= 10

    first = mappings[0]
    assert "id" in first
    assert "control_code" in first
    assert "requirement_identifier" in first
    assert "framework_code" in first
    assert "approval_status" in first
    assert "mapping_rationale" in first


def test_mappings_filtering(client):
    """
    Ensure GET /api/v1/mappings supports filtering by framework and approval status.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Filter by SOC 2
    res_soc2 = client.get(f"{settings.API_V1_STR}/mappings?framework_code=SOC2", headers=headers)
    assert res_soc2.status_code == 200
    soc2_maps = res_soc2.json()
    assert len(soc2_maps) > 0
    assert all(m["framework_code"] == "SOC2" for m in soc2_maps)

    # 2. Filter by ISO 27001
    res_iso = client.get(f"{settings.API_V1_STR}/mappings?framework_code=ISO27001", headers=headers)
    assert res_iso.status_code == 200
    iso_maps = res_iso.json()
    assert len(iso_maps) > 0
    assert all(m["framework_code"] == "ISO27001" for m in iso_maps)

    # 3. Filter by Approval Status
    res_approved = client.get(
        f"{settings.API_V1_STR}/mappings?approval_status={MappingApprovalStatus.APPROVED.value}",
        headers=headers
    )
    assert res_approved.status_code == 200
    assert all(m["approval_status"] == MappingApprovalStatus.APPROVED.value for m in res_approved.json())


def test_create_mapping_success_and_duplicate_prevention(client):
    """
    Ensure creating a cross-framework mapping works, and duplicate mappings are rejected.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # First fetch available controls and requirements
    ctrls_res = client.get(f"{settings.API_V1_STR}/controls", headers=headers)
    assert ctrls_res.status_code == 200
    controls = ctrls_res.json()
    # Find CTL-BCP-01
    target_ctrl = next(c for c in controls if c["control_id"] == "CTL-BCP-01")

    reqs_res = client.get(f"{settings.API_V1_STR}/frameworks/requirements?framework_code=SOC2")
    assert reqs_res.status_code == 200
    reqs = reqs_res.json()
    # Find CC1.1
    target_req = next(r for r in reqs if r["identifier"] == "CC1.1")

    payload = {
        "control_id": target_ctrl["id"],
        "requirement_id": target_req["id"],
        "mapping_rationale": "Business continuity policies incorporate executive ethical oversight and continuity commitments.",
        "approval_status": "PROPOSED"
    }

    # 1. Create mapping
    create_res = client.post(f"{settings.API_V1_STR}/mappings", json=payload, headers=headers)
    assert create_res.status_code == 201
    data = create_res.json()
    assert data["control_code"] == "CTL-BCP-01"
    assert data["requirement_identifier"] == "CC1.1"
    assert data["approval_status"] == "PROPOSED"
    mapping_id = data["id"]

    # 2. Duplicate mapping must be rejected with 400 Bad Request
    dup_res = client.post(f"{settings.API_V1_STR}/mappings", json=payload, headers=headers)
    assert dup_res.status_code == 400
    assert "already mapped" in dup_res.json()["detail"].lower()

    # Clean up test mapping
    del_res = client.delete(f"{settings.API_V1_STR}/mappings/{mapping_id}", headers=headers)
    assert del_res.status_code == 204


def test_mapping_review_approval_workflow(client):
    """
    Ensure GRC Analyst can formally review and approve a proposed mapping.
    """
    analyst_token = get_token(client, "analyst@apexcloud.io")
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Create temporary proposed mapping
    ctrls_res = client.get(f"{settings.API_V1_STR}/controls", headers=analyst_headers)
    c_id = ctrls_res.json()[0]["id"]

    reqs_res = client.get(f"{settings.API_V1_STR}/frameworks/requirements?framework_code=SOC2")
    r_id = next(r["id"] for r in reqs_res.json() if r["identifier"] == "CC1.1")

    # Create proposed mapping
    create_res = client.post(
        f"{settings.API_V1_STR}/mappings",
        json={
            "control_id": c_id,
            "requirement_id": r_id,
            "mapping_rationale": "Governance oversight mapping test for sign-off review.",
            "approval_status": "PROPOSED"
        },
        headers=analyst_headers
    )
    assert create_res.status_code == 201
    map_id = create_res.json()["id"]

    # Approve the mapping
    review_res = client.post(
        f"{settings.API_V1_STR}/mappings/{map_id}/review",
        json={"approval_status": "APPROVED", "review_comment": "Verified against SOC 2 criteria documentation."},
        headers=analyst_headers
    )
    assert review_res.status_code == 200
    review_data = review_res.json()
    assert review_data["approval_status"] == "APPROVED"
    assert review_data["reviewed_by_name"] is not None
    assert review_data["reviewed_at"] is not None

    # Cleanup
    client.delete(f"{settings.API_V1_STR}/mappings/{map_id}", headers=analyst_headers)


def test_mapping_review_rbac_restricted(client):
    """
    Ensure Auditor and Control Owner cannot approve mappings (restricted to GRC Analyst / Admin).
    """
    auditor_token = get_token(client, "auditor@cpa-assurance.com")
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    # Try to review mapping 1 as Auditor
    res = client.post(
        f"{settings.API_V1_STR}/mappings/1/review",
        json={"approval_status": "APPROVED"},
        headers=auditor_headers
    )
    assert res.status_code == 403


def test_cross_framework_matrix_endpoint(client):
    """
    Ensure GET /api/v1/mappings/matrix returns controls mapped side-by-side across frameworks.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/mappings/matrix", headers=headers)
    assert response.status_code == 200
    matrix = response.json()
    assert isinstance(matrix, list)
    assert len(matrix) >= 5

    # Check MFA control (CTL-IAM-01) mapping
    mfa_row = next((r for r in matrix if r["control_id"] == "CTL-IAM-01"), None)
    assert mfa_row is not None
    assert len(mfa_row["soc2_mappings"]) > 0
    assert len(mfa_row["iso27001_mappings"]) > 0
    assert len(mfa_row["nist_csf_mappings"]) > 0
    assert mfa_row["total_mappings"] >= 3


def test_assessments_summary_readiness_metrics(client):
    """
    Ensure GET /api/v1/assessments/summary computes explicit mathematical readiness scores,
    declares applicable denominators, and enforces non-certification notices.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/assessments/summary", headers=headers)
    assert response.status_code == 200
    summaries = response.json()
    assert len(summaries) == 3  # SOC2, ISO27001, NIST_CSF

    soc2_sum = next(s for s in summaries if s["framework_code"] == "SOC2")
    assert soc2_sum["total_requirements"] > 0
    assert soc2_sum["applicable_requirements"] <= soc2_sum["total_requirements"]
    assert "Strict Readiness" in soc2_sum["formula_explanation"]
    assert "Weighted Readiness" in soc2_sum["formula_explanation"]
    assert "In-Scope" in soc2_sum["scope_definition"]

    # Verify NIST CSF disclaimer in summary
    nist_sum = next(s for s in summaries if s["framework_code"] == "NIST_CSF")
    assert nist_sum["is_certification"] is False
    assert "Voluntary" in nist_sum["assurance_type"]


def test_assessment_upsert_mandatory_not_applicable_justification(client):
    """
    Ensure marking a requirement as NOT_APPLICABLE strictly requires a documented justification.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch any requirement ID
    reqs_res = client.get(f"{settings.API_V1_STR}/frameworks/requirements?framework_code=SOC2")
    req_id = reqs_res.json()[0]["id"]

    # 1. Attempt NOT_APPLICABLE with empty justification -> Must fail with 422
    invalid_payload = {
        "requirement_id": req_id,
        "status": AssessmentStatus.NOT_APPLICABLE.value,
        "justification": "   "  # Whitespace only
    }
    fail_res = client.post(f"{settings.API_V1_STR}/assessments", json=invalid_payload, headers=headers)
    assert fail_res.status_code == 422

    # 2. Attempt NOT_APPLICABLE with valid justification -> Must succeed (200)
    valid_payload = {
        "requirement_id": req_id,
        "status": AssessmentStatus.NOT_APPLICABLE.value,
        "justification": "ApexCloud operates as a pure cloud multi-tenant SaaS provider with no physical client-facing facilities.",
        "identified_gaps": None,
        "recommended_actions": None
    }
    success_res = client.post(f"{settings.API_V1_STR}/assessments", json=valid_payload, headers=headers)
    assert success_res.status_code == 200
    data = success_res.json()
    assert data["status"] == AssessmentStatus.NOT_APPLICABLE.value
    assert "pure cloud" in data["justification"]


def test_web_views_mappings_and_assessments(client):
    """
    Ensure HTML pages for Mappings Matrix and Gap Assessment dashboard render properly.
    """
    # 1. Mappings Matrix HTML
    res_matrix = client.get("/mappings")
    assert res_matrix.status_code == 200
    assert "text/html" in res_matrix.headers["content-type"]
    assert "Cross-Framework Mapping Matrix" in res_matrix.text
    assert "CTL-IAM-01" in res_matrix.text

    # 2. Mappings Catalog List HTML
    res_list = client.get("/mappings?view_mode=list")
    assert res_list.status_code == 200
    assert "text/html" in res_list.headers["content-type"]
    assert "Technical Justification & Rationale" in res_list.text

    # 3. Gap Assessment Dashboard HTML
    res_assess = client.get("/assessments?framework=SOC2")
    assert res_assess.status_code == 200
    assert "text/html" in res_assess.headers["content-type"]
    assert "Compliance Readiness & Gap Assessment" in res_assess.text
    assert "Strict Readiness" in res_assess.text
    assert "Weighted Readiness" in res_assess.text
