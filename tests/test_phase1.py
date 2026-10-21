import pytest
from app.core.config import settings
from app.core.logging import log_security_event


def test_health_check_endpoint(client):
    """
    Ensure the /api/health endpoint returns 200 OK and valid health telemetry.
    """
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "project" in data
    assert "version" in data
    assert "timestamp" in data
    assert "database" in data


def test_readiness_check_endpoint(client):
    """
    Ensure the /api/ready endpoint validates file vault accessibility.
    """
    response = client.get("/api/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["ready"] is True
    assert data["checks"]["evidence_vault_writable"] is True
    assert "pdf" in data["checks"]["allowed_extensions"]


def test_security_headers_applied(client):
    """
    Verify that OWASP-recommended security headers are injected into HTTP responses.
    """
    response = client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-XSS-Protection"] == "1; mode=block"
    assert "strict-origin-when-cross-origin" in response.headers["Referrer-Policy"]
    assert "Content-Security-Policy" in response.headers


def test_root_index_page(client):
    """
    Ensure the homepage template renders semantic HTML and framework references.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    body = response.text
    assert "SOC 2" in body
    assert "ISO/IEC 27001" in body
    assert "NIST CSF 2.0" in body
    assert "Voluntary guidance framework" in body or "NIST CSF is a voluntary guidance" in body


def test_settings_properties(current_settings):
    """
    Verify Settings helper properties for extensions and upload paths.
    """
    assert "pdf" in current_settings.allowed_extensions_set
    assert "png" in current_settings.allowed_extensions_set
    assert current_settings.max_upload_size_bytes == current_settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    assert current_settings.resolved_upload_dir.exists()


def test_security_audit_logger():
    """
    Verify that security audit events log cleanly across all severity levels.
    """
    # This should execute without throwing any exception
    log_security_event(
        event_type="TEST_EVENT",
        status="SUCCESS",
        user_email="auditor@example.com",
        org_id=1,
        client_ip="127.0.0.1",
        resource="Control:AC-01",
        details={"action": "test_verification"},
        severity="INFO"
    )

    log_security_event(
        event_type="AUTH_FAILURE",
        status="FAILURE",
        user_email="intruder@example.com",
        client_ip="192.168.1.100",
        details={"reason": "bad_password"},
        severity="WARNING"
    )


def test_api_not_found_returns_json(client):
    """
    Ensure 404 on /api/* returns JSON, not HTML.
    """
    response = client.get("/api/nonexistent-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["path"] == "/api/nonexistent-endpoint"
