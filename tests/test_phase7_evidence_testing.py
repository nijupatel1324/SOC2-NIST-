import os
import io
import pytest
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter
from app.models.enums import EvidenceReviewStatus, TestResult


@pytest.fixture(autouse=True)
def clean_test_environment(client):
    """Ensure test client cookies, rate limiter, and test database records are cleaned."""
    from app.db.session import SessionLocal
    from app.models import EvidenceRecord, ControlTest, AuditProject

    created_file_paths = []

    def cleanup_records():
        db = SessionLocal()
        try:
            # Delete test-created control tests
            db.query(ControlTest).filter(
                ControlTest.test_title.like("%[TEST-PHASE7]%")
            ).delete(synchronize_session=False)

            # Delete test-created audit projects
            db.query(AuditProject).filter(
                AuditProject.name.like("%[TEST-PHASE7]%")
            ).delete(synchronize_session=False)

            # Find test-created evidence records and collect file paths
            test_evs = db.query(EvidenceRecord).filter(
                EvidenceRecord.title.like("%[TEST-PHASE7]%")
            ).all()
            for ev in test_evs:
                if ev.stored_file_path and os.path.exists(ev.stored_file_path):
                    try:
                        os.remove(ev.stored_file_path)
                    except OSError:
                        pass
                db.delete(ev)

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


def test_evidence_upload_valid_file(client):
    """
    Ensure POST /api/v1/evidence/upload accepts valid file, computes SHA-256,
    and returns quarantined metadata.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    test_content = b"user_id,mfa_active,last_login\n101,true,2026-03-01\n102,false,2026-03-02\n"
    file_tuple = ("iam_report.csv", io.BytesIO(test_content), "text/csv")

    response = client.post(
        f"{settings.API_V1_STR}/evidence/upload",
        headers=headers,
        data={
            "title": "[TEST-PHASE7] IAM Security Report",
            "description": "Evidence demonstrating multi-factor authentication enrollment verification.",
            "control_id": 1
        },
        files={"file": file_tuple}
    )

    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "[TEST-PHASE7] IAM Security Report"
    assert "iam_report.csv" in data["file_name"]
    assert len(data["sha256_hash"]) == 64
    assert data["file_size_bytes"] == len(test_content)
    assert data["review_status"] == "PENDING_REVIEW"
    assert data["control_id"] == 1


def test_evidence_upload_rejected_dangerous_extension(client):
    """
    Ensure POST /api/v1/evidence/upload rejects unpermitted file extensions (.exe, .sh, .py).
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    script_content = b"#!/bin/bash\necho 'Malicious shell payload'\n"
    file_tuple = ("payload.sh", io.BytesIO(script_content), "application/x-sh")

    response = client.post(
        f"{settings.API_V1_STR}/evidence/upload",
        headers=headers,
        data={
            "title": "[TEST-PHASE7] Shell Script Upload",
            "description": "Testing boundary rejection for shell scripts.",
            "control_id": 1
        },
        files={"file": file_tuple}
    )

    assert response.status_code == 400
    assert "prohibited in the Evidence Vault" in response.json()["detail"]


def test_evidence_download_streaming(client):
    """
    Ensure GET /api/v1/evidence/{evidence_id}/download streams file bytes correctly.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    sample_bytes = b"CONFIDENTIAL AUDIT SAMPLE: Server hardening log dump verified."
    file_tuple = ("hardening_log.txt", io.BytesIO(sample_bytes), "text/plain")

    up_res = client.post(
        f"{settings.API_V1_STR}/evidence/upload",
        headers=headers,
        data={
            "title": "[TEST-PHASE7] Hardening Log Artifact",
            "description": "Baseline hardening script output for Linux cluster.",
            "control_id": 1
        },
        files={"file": file_tuple}
    )
    assert up_res.status_code == 201
    evidence_id = up_res.json()["id"]

    # Stream download
    dl_res = client.get(f"{settings.API_V1_STR}/evidence/{evidence_id}/download", headers=headers)
    assert dl_res.status_code == 200
    assert dl_res.content == sample_bytes
    assert "attachment" in dl_res.headers.get("content-disposition", "")


def test_evidence_sha256_integrity_verification_and_tamper_detection(client):
    """
    Ensure GET /api/v1/evidence/{evidence_id}/verify verifies intact files and detects tampering.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    original_bytes = b"ORGANIZATION ROOT OF TRUST VERIFIED PASS"
    file_tuple = ("root_of_trust.txt", io.BytesIO(original_bytes), "text/plain")

    up_res = client.post(
        f"{settings.API_V1_STR}/evidence/upload",
        headers=headers,
        data={
            "title": "[TEST-PHASE7] Cryptographic Tamper Test Artifact",
            "description": "Target artifact for demonstrating SHA-256 tamper resilience.",
            "control_id": 1
        },
        files={"file": file_tuple}
    )
    assert up_res.status_code == 201
    ev_data = up_res.json()
    evidence_id = ev_data["id"]

    # 1. Verify Intact file
    v_res = client.get(f"{settings.API_V1_STR}/evidence/{evidence_id}/verify", headers=headers)
    assert v_res.status_code == 200
    v_data = v_res.json()
    assert v_data["is_valid"] is True
    assert v_data["status"] == "VERIFIED_INTACT"
    assert v_data["database_hash"] == v_data["calculated_hash"]

    # 2. Simulate disk tampering / unauthorized modification
    from app.db.session import SessionLocal
    from app.models import EvidenceRecord

    db = SessionLocal()
    try:
        ev_record = db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first()
        assert ev_record is not None
        file_disk_path = ev_record.stored_file_path
        # Tamper the file contents on disk
        with open(file_disk_path, "wb") as f:
            f.write(b"CORRUPTED OR MALICIOUSLY INJECTED PAYLOAD CONTENT")
    finally:
        db.close()

    # 3. Re-verify integrity -> Expect TAMPERED detection
    tamper_res = client.get(f"{settings.API_V1_STR}/evidence/{evidence_id}/verify", headers=headers)
    assert tamper_res.status_code == 200
    tamper_data = tamper_res.json()
    assert tamper_data["is_valid"] is False
    assert tamper_data["status"] == "INTEGRITY_COMPROMISED"
    assert tamper_data["database_hash"] != tamper_data["calculated_hash"]


def test_evidence_auditor_review_workflow(client):
    """
    Ensure POST /api/v1/evidence/{evidence_id}/review enforces role permissions
    and updates review status with audit tracking.
    """
    # 1. Analyst uploads evidence
    analyst_token = get_token(client, "analyst@apexcloud.io")
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    file_tuple = ("access_review.txt", io.BytesIO(b"Quarterly access review completed."), "text/plain")
    up_res = client.post(
        f"{settings.API_V1_STR}/evidence/upload",
        headers=headers_analyst,
        data={
            "title": "[TEST-PHASE7] Access Review Export",
            "description": "User access review documentation for SOC 2 CC6.1.",
            "control_id": 1
        },
        files={"file": file_tuple}
    )
    assert up_res.status_code == 201
    evidence_id = up_res.json()["id"]

    # 2. Control Owner attempts review -> Expect 403 Forbidden
    owner_token = get_token(client, "it.owner@apexcloud.io")
    headers_owner = {"Authorization": f"Bearer {owner_token}"}
    forbidden_res = client.post(
        f"{settings.API_V1_STR}/evidence/{evidence_id}/review",
        headers=headers_owner,
        json={"status": "APPROVED", "review_notes": "I approve my own control evidence"}
    )
    assert forbidden_res.status_code == 403

    # 3. Auditor approves evidence
    auditor_token = get_token(client, "auditor@cpa-assurance.com")
    headers_auditor = {"Authorization": f"Bearer {auditor_token}"}
    approve_res = client.post(
        f"{settings.API_V1_STR}/evidence/{evidence_id}/review",
        headers=headers_auditor,
        json={"status": "APPROVED", "review_notes": "Sampling verified against active directory extract."}
    )
    assert approve_res.status_code == 200
    approved_data = approve_res.json()
    assert approved_data["review_status"] == "APPROVED"
    assert approved_data["reviewed_by_id"] is not None

    # 4. Auditor can update review to REJECTED if deficiency found
    reject_res = client.post(
        f"{settings.API_V1_STR}/evidence/{evidence_id}/review",
        headers=headers_auditor,
        json={"status": "REJECTED", "review_notes": "Sample date falls outside audit period window."}
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["review_status"] == "REJECTED"


def test_audit_campaign_lifecycle(client):
    """
    Ensure GET and POST /api/v1/audits/projects manage audit campaigns.
    """
    token = get_token(client, "analyst@apexcloud.io")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. List existing projects
    res_list = client.get(f"{settings.API_V1_STR}/audits/projects", headers=headers)
    assert res_list.status_code == 200
    projects = res_list.json()
    assert isinstance(projects, list)
    assert len(projects) >= 1

    # 2. Create new audit project
    new_proj = {
        "name": "[TEST-PHASE7] 2026 ISO 27001 Surveillance Assessment",
        "framework_id": 2,  # ISO 27001:2022
        "audit_type": "ISO27001_SURVEILLANCE",
        "period_start": "2026-06-01T00:00:00Z",
        "period_end": "2026-06-30T23:59:59Z",
        "status": "IN_PROGRESS"
    }
    create_res = client.post(f"{settings.API_V1_STR}/audits/projects", headers=headers, json=new_proj)
    assert create_res.status_code == 201
    data = create_res.json()
    assert data["name"] == new_proj["name"]
    assert data["framework_code"] == "ISO27001"
    assert data["status"] == "IN_PROGRESS"


def test_control_test_execution_and_timestamp_update(client):
    """
    Ensure POST /api/v1/audits/tests records control test result (PASS/FAIL)
    and automatically updates the control's last_tested_at timestamp.
    """
    token = get_token(client, "auditor@cpa-assurance.com")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch target control before testing
    ctrl_res = client.get(f"{settings.API_V1_STR}/controls/CTL-IAM-01", headers=headers)
    assert ctrl_res.status_code == 200
    ctrl_id = ctrl_res.json()["id"]

    # 2. Record control test execution
    test_payload = {
        "control_id": ctrl_id,
        "test_title": "[TEST-PHASE7] MFA Configuration Inspection",
        "test_objective": "Verify MFA enforcement policy applies to 100% of cloud console logins.",
        "test_procedure": "Sampled 30 randomly selected user sessions from Okta and AWS IAM logs.",
        "result": "PASS",
        "sample_size": 30,
        "exceptions_identified": 0,
        "notes": "All sampled identities demonstrated active hardware/TOTP MFA challenges."
    }
    test_res = client.post(f"{settings.API_V1_STR}/audits/tests", headers=headers, json=test_payload)
    assert test_res.status_code == 201
    test_data = test_res.json()
    assert test_data["test_title"] == test_payload["test_title"]
    assert test_data["result"] == "PASS"
    assert test_data["sample_size"] == 30
    assert test_data["exceptions_identified"] == 0

    # 3. Verify control's last_tested_at was updated
    ctrl_updated = client.get(f"{settings.API_V1_STR}/controls/CTL-IAM-01", headers=headers).json()
    assert ctrl_updated["last_tested_at"] is not None

    # 4. Verify test filtering by result
    filter_res = client.get(f"{settings.API_V1_STR}/audits/tests?result=PASS", headers=headers)
    assert filter_res.status_code == 200
    pass_tests = filter_res.json()
    assert any(t["id"] == test_data["id"] for t in pass_tests)


def test_web_ui_evidence_and_audits_pages(client):
    """
    Ensure web UI endpoints /evidence and /audits render valid HTML with governance components.
    """
    # 1. Test Evidence Vault Web Page
    ev_res = client.get("/evidence")
    assert ev_res.status_code == 200
    assert "Cryptographic Evidence Vault" in ev_res.text
    assert "SHA-256" in ev_res.text
    assert "Upload Evidence File" in ev_res.text

    # 2. Test Evidence Vault Filtered
    ev_filter_res = client.get("/evidence?status_filter=APPROVED")
    assert ev_filter_res.status_code == 200
    assert "Cryptographic Evidence Vault" in ev_filter_res.text

    # 3. Test Audit Projects & Testing Web Page
    audit_res = client.get("/audits")
    assert audit_res.status_code == 200
    assert "Audit Projects &amp; Control Testing" in audit_res.text or "Audit Projects & Control Testing" in audit_res.text
    assert "Independent Assurance &amp; Certification Notice" in audit_res.text or "Independent Assurance & Certification Notice" in audit_res.text
    assert "Total Tests Executed" in audit_res.text

    # 4. Test Audits Filtered
    audit_filter_res = client.get("/audits?result_filter=PASS")
    assert audit_filter_res.status_code == 200
    assert "Audit Projects" in audit_filter_res.text
