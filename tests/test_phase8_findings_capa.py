import pytest
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter
from app.models.enums import FindingSeverity, FindingStatus, ActionStatus


@pytest.fixture(autouse=True)
def clean_test_environment(client):
    """Ensure test client cookies, rate limiter, and test database records are cleaned."""
    from app.db.session import SessionLocal
    from app.models import AuditFinding, CorrectiveAction

    def cleanup_records():
        db = SessionLocal()
        try:
            # Delete actions for test findings
            test_findings = db.query(AuditFinding).filter(
                AuditFinding.finding_id.like("FND-TEST-%")
            ).all()
            for tf in test_findings:
                db.query(CorrectiveAction).filter(CorrectiveAction.finding_id == tf.id).delete()
                db.delete(tf)
            db.commit()
        finally:
            db.close()

    cleanup_records()
    login_rate_limiter.reset()
    client.cookies.clear()
    yield
    cleanup_records()
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


def test_list_findings(client):
    """
    Ensure GET /api/v1/findings lists organization deficiencies and includes seeded scenario.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/findings", headers=headers)
    assert response.status_code == 200
    findings = response.json()
    assert isinstance(findings, list)
    assert len(findings) >= 1

    # Verify seeded demonstration finding FND-2026-001
    fnd = next((f for f in findings if f["finding_id"] == "FND-2026-001"), None)
    assert fnd is not None
    assert "MFA" in fnd["title"]
    assert fnd["severity"] == "HIGH"
    assert fnd["status"] in ["OPEN", "REMEDIATION_IN_PROGRESS"]
    assert "Root Cause:" in fnd["root_cause"] or len(fnd["root_cause"]) > 10
    assert "CC6.1" in fnd["business_impact"] or len(fnd["business_impact"]) > 10


def test_filter_findings_by_status_and_severity(client):
    """
    Ensure GET /api/v1/findings supports status and severity filtering.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Filter by severity
    res_high = client.get(f"{settings.API_V1_STR}/findings?severity=HIGH", headers=headers)
    assert res_high.status_code == 200
    high_findings = res_high.json()
    assert len(high_findings) >= 1
    assert all(f["severity"] == "HIGH" for f in high_findings)

    # 2. Filter by status
    res_status = client.get(f"{settings.API_V1_STR}/findings?status=REMEDIATION_IN_PROGRESS", headers=headers)
    assert res_status.status_code == 200
    assert all(f["status"] == "REMEDIATION_IN_PROGRESS" for f in res_status.json())


def test_get_single_finding_detail(client):
    """
    Ensure GET /api/v1/findings/{finding_identifier} returns complete details and CAPA actions.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{settings.API_V1_STR}/findings/FND-2026-001", headers=headers)
    assert response.status_code == 200
    fnd = response.json()
    assert fnd["finding_id"] == "FND-2026-001"
    assert "corrective_actions" in fnd
    assert isinstance(fnd["corrective_actions"], list)
    assert len(fnd["corrective_actions"]) >= 1

    action = fnd["corrective_actions"][0]
    assert "action_plan" in action
    assert action["status"] in ["OPEN", "IN_PROGRESS", "IMPLEMENTED", "VERIFIED"]


def test_create_finding_api_and_duplicate_rejection(client):
    """
    Ensure POST /api/v1/findings documents new deficiency and rejects duplicates.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch a valid control ID
    ctrl_res = client.get(f"{settings.API_V1_STR}/controls/CTL-IAM-01", headers=headers)
    assert ctrl_res.status_code == 200
    ctrl_id = ctrl_res.json()["id"]

    new_finding = {
        "finding_id": "FND-TEST-001",
        "control_id": ctrl_id,
        "title": "[TEST-PHASE8] Missing Database Encryption at Rest on Analytics Replica",
        "severity": "HIGH",
        "root_cause": "Terraform module for staging analytics database omitted storage_encrypted=true flag.",
        "business_impact": "Potential non-conformity with SOC 2 CC6.6 and ISO 27001 Annex A.8.24.",
        "due_date": "2026-07-15T00:00:00Z"
    }

    create_res = client.post(f"{settings.API_V1_STR}/findings", headers=headers, json=new_finding)
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["finding_id"] == "FND-TEST-001"
    assert created_data["severity"] == "HIGH"
    assert created_data["status"] == "OPEN"

    # Attempt duplicate finding_id -> Expect 400 Bad Request
    dup_res = client.post(f"{settings.API_V1_STR}/findings", headers=headers, json=new_finding)
    assert dup_res.status_code == 400
    assert "already exists" in dup_res.json()["detail"]


def test_corrective_action_plan_lifecycle(client):
    """
    Ensure POST /api/v1/findings/{id}/actions creates CAPA items and transitions finding status.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create target test finding
    ctrl_res = client.get(f"{settings.API_V1_STR}/controls/CTL-IAM-01", headers=headers)
    ctrl_id = ctrl_res.json()["id"]

    fnd_res = client.post(
        f"{settings.API_V1_STR}/findings",
        headers=headers,
        json={
            "finding_id": "FND-TEST-CAPA",
            "control_id": ctrl_id,
            "title": "[TEST-PHASE8] CAPA Lifecycle Target",
            "severity": "MEDIUM",
            "root_cause": "Process gap in quarterly employee offboarding checklist.",
            "business_impact": "Orphan accounts remaining active post-separation.",
        }
    )
    assert fnd_res.status_code == 201
    assert fnd_res.json()["status"] == "OPEN"

    # 2. Add corrective action plan
    action_payload = {
        "action_plan": "Implement automated SCIM deprovisioning connector between Workday HR and Okta IdP.",
        "target_completion_date": "2026-08-01T00:00:00Z",
        "notes": "Coordinating with HR Operations team for testing."
    }
    action_res = client.post(
        f"{settings.API_V1_STR}/findings/FND-TEST-CAPA/actions",
        headers=headers,
        json=action_payload
    )
    assert action_res.status_code == 201
    action_data = action_res.json()
    assert action_data["status"] == "OPEN"
    action_id = action_data["id"]

    # 3. Check finding automatically transitioned to REMEDIATION_IN_PROGRESS
    fnd_updated = client.get(f"{settings.API_V1_STR}/findings/FND-TEST-CAPA", headers=headers).json()
    assert fnd_updated["status"] == "REMEDIATION_IN_PROGRESS"

    # 4. Advance action to IMPLEMENTED
    patch_res = client.patch(
        f"{settings.API_V1_STR}/findings/FND-TEST-CAPA/actions/{action_id}",
        headers=headers,
        json={"status": "IMPLEMENTED", "notes": "Connector deployed to staging and production."}
    )
    assert patch_res.status_code == 200
    patched_data = patch_res.json()
    assert patched_data["status"] == "IMPLEMENTED"
    assert patched_data["actual_completion_date"] is not None


def test_finding_closure_workflow_and_rbac(client):
    """
    Ensure POST /api/v1/findings/{id}/close requires ORG_ADMIN or AUDITOR role,
    records closure statement, and marks finding CLOSED.
    """
    analyst_token = get_token(client, "analyst@apexcloud.io")
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    # 1. Create finding
    ctrl_res = client.get(f"{settings.API_V1_STR}/controls/CTL-IAM-01", headers=headers_analyst)
    ctrl_id = ctrl_res.json()["id"]

    client.post(
        f"{settings.API_V1_STR}/findings",
        headers=headers_analyst,
        json={
            "finding_id": "FND-TEST-CLOSE",
            "control_id": ctrl_id,
            "title": "[TEST-PHASE8] Closure Test Deficiency",
            "severity": "LOW",
            "root_cause": "Typo in internal password rotation wiki documentation.",
            "business_impact": "User confusion regarding 90-day vs 180-day rotation cadence.",
        }
    )

    # 2. Control Owner attempts to close -> Expect 403 Forbidden
    owner_token = get_token(client, "it.owner@apexcloud.io")
    headers_owner = {"Authorization": f"Bearer {owner_token}"}
    forbidden_res = client.post(
        f"{settings.API_V1_STR}/findings/FND-TEST-CLOSE/close",
        headers=headers_owner,
        json={"closure_notes": "I fixed the documentation.", "resolution_status": "CLOSED"}
    )
    assert forbidden_res.status_code == 403

    # 3. Auditor authorizes closure
    auditor_token = get_token(client, "auditor@cpa-assurance.com")
    headers_auditor = {"Authorization": f"Bearer {auditor_token}"}
    close_res = client.post(
        f"{settings.API_V1_STR}/findings/FND-TEST-CLOSE/close",
        headers=headers_auditor,
        json={
            "closure_notes": "Auditor verified wiki update matches published Information Security Policy v2.4. Non-conformity closed.",
            "resolution_status": "CLOSED"
        }
    )
    assert close_res.status_code == 200
    closed_data = close_res.json()
    assert closed_data["status"] == "CLOSED"
    assert closed_data["closed_at"] is not None
    assert closed_data["closed_by_name"] is not None


def test_web_ui_findings_and_detail_pages(client):
    """
    Ensure web UI endpoints /findings and /findings/{id} render valid HTML.
    """
    # 1. Findings Register Overview
    res_list = client.get("/findings")
    assert res_list.status_code == 200
    assert "Audit Findings" in res_list.text
    assert "Total Logged Deficiencies" in res_list.text
    assert "FND-2026-001" in res_list.text

    # 2. Filtered View
    res_filtered = client.get("/findings?severity_filter=HIGH")
    assert res_filtered.status_code == 200
    assert "FND-2026-001" in res_filtered.text

    # 3. Finding Deep-Dive Detail View
    res_detail = client.get("/findings/FND-2026-001")
    assert res_detail.status_code == 200
    assert "Root-Cause Analysis" in res_detail.text
    assert "Audit &amp; Business Exposure Impact" in res_detail.text or "Audit & Business Exposure Impact" in res_detail.text
    assert "Corrective Action Plans (CAPA)" in res_detail.text
    assert "Deficient Security Control" in res_detail.text
