import pytest
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter


@pytest.fixture(autouse=True)
def reset_limiter_and_cookies(client):
    """Reset rate limiter state and clear test client cookies before each test."""
    login_rate_limiter.reset()
    client.cookies.clear()
    yield
    login_rate_limiter.reset()
    client.cookies.clear()


def test_api_login_success(client):
    """
    Ensure POST /api/v1/auth/login authenticates valid user,
    returns JWT access token, and sets secure HttpOnly cookie.
    """
    payload = {
        "email": "security.lead@apexcloud.io",
        "password": "Password123!"
    }
    response = client.post(f"{settings.API_V1_STR}/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "security.lead@apexcloud.io"
    assert data["user"]["role"] == "ORG_ADMIN"

    # Verify session cookie was set
    assert settings.COOKIE_NAME in response.cookies


def test_api_login_invalid_password(client):
    """
    Ensure invalid password returns 401 Unauthorized.
    """
    payload = {
        "email": "security.lead@apexcloud.io",
        "password": "IncorrectPassword!"
    }
    response = client.post(f"{settings.API_V1_STR}/auth/login", json=payload)
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


def test_api_login_unknown_user(client):
    """
    Ensure unknown user returns 401 Unauthorized.
    """
    payload = {
        "email": "nonexistent@apexcloud.io",
        "password": "Password123!"
    }
    response = client.post(f"{settings.API_V1_STR}/auth/login", json=payload)
    assert response.status_code == 401


def test_auth_me_with_bearer_token(client):
    """
    Ensure GET /api/v1/auth/me resolves identity from Authorization Bearer header.
    """
    login_res = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "analyst@apexcloud.io", "password": "Password123!"}
    )
    token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get(f"{settings.API_V1_STR}/auth/me", headers=headers)
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == "analyst@apexcloud.io"
    assert me_data["role"] == "GRC_ANALYST"


def test_auth_me_unauthorized_without_token(client):
    """
    Ensure GET /api/v1/auth/me without token returns 401.
    """
    response = client.get(f"{settings.API_V1_STR}/auth/me")
    assert response.status_code == 401


def test_rbac_permissions_enforcement(client):
    """
    Validate Role-Based Access Control (RBAC):
    - Org Admin can access /test/admin-only.
    - GRC Analyst is blocked (403) from /test/admin-only.
    - Platform Admin has global override.
    """
    # 1. Login as GRC Analyst
    res_analyst = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "analyst@apexcloud.io", "password": "Password123!"}
    )
    analyst_token = res_analyst.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # GRC Analyst attempting Admin-only endpoint -> 403 Forbidden
    resp = client.get("/api/v1/test/admin-only", headers=analyst_headers)
    assert resp.status_code == 403
    assert "Access forbidden" in resp.json()["detail"]

    # GRC Analyst accessing Analyst-only endpoint -> 200 OK
    resp_ok = client.get("/api/v1/test/analyst-only", headers=analyst_headers)
    assert resp_ok.status_code == 200

    # 2. Login as Org Admin
    res_admin = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "security.lead@apexcloud.io", "password": "Password123!"}
    )
    admin_token = res_admin.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Org Admin accessing Admin-only endpoint -> 200 OK
    resp_admin = client.get("/api/v1/test/admin-only", headers=admin_headers)
    assert resp_admin.status_code == 200

    # 3. Login as Platform Admin (Global Override)
    res_plat = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "admin@apexcloud.io", "password": "Password123!"}
    )
    plat_token = res_plat.json()["access_token"]
    plat_headers = {"Authorization": f"Bearer {plat_token}"}

    # Platform Admin can access admin-only, analyst-only, and auditor-only
    assert client.get("/api/v1/test/admin-only", headers=plat_headers).status_code == 200
    assert client.get("/api/v1/test/analyst-only", headers=plat_headers).status_code == 200
    assert client.get("/api/v1/test/auditor-only", headers=plat_headers).status_code == 200


def test_multi_tenant_isolation(client):
    """
    Ensure tenant isolation prevents users from accessing other organizations' data.
    """
    # Login as Org Admin of ApexCloud (org_id = 1)
    res = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "security.lead@apexcloud.io", "password": "Password123!"}
    )
    token = res.json()["access_token"]
    org_id = res.json()["user"]["organization_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Own organization access is permitted
    resp_own = client.get(f"/api/v1/test/org/{org_id}/resource", headers=headers)
    assert resp_own.status_code == 200

    # Foreign organization access (org_id 999) is strictly forbidden (403)
    resp_foreign = client.get("/api/v1/test/org/999/resource", headers=headers)
    assert resp_foreign.status_code == 403
    assert "Cross-organization data access strictly prohibited" in resp_foreign.json()["detail"]


def test_web_login_and_logout_flow(client):
    """
    Ensure web browser HTML login form sets cookie and logout clears it.
    """
    # 1. GET /login renders HTML
    get_res = client.get("/login")
    assert get_res.status_code == 200
    assert "Compliance Portal Sign In" in get_res.text
    assert "Password123!" in get_res.text

    # 2. POST /login form submission
    form_data = {
        "email": "security.lead@apexcloud.io",
        "password": "Password123!"
    }
    post_res = client.post("/login", data=form_data, follow_redirects=False)
    assert post_res.status_code == 302
    assert post_res.headers["location"] == "/"
    assert settings.COOKIE_NAME in post_res.cookies

    # 3. GET / with persisted session cookie shows authenticated user badge
    home_res = client.get("/")
    assert home_res.status_code == 200
    assert "Sarah" in home_res.text
    assert "ORG_ADMIN" in home_res.text
    assert "Sign Out" in home_res.text

    # 4. GET /logout clears cookie
    logout_res = client.get("/logout", follow_redirects=False)
    assert logout_res.status_code == 302
    assert logout_res.headers["location"] == "/login"

    # 5. Subsequent GET / shows anonymous navbar with Sign In link
    anon_res = client.get("/")
    assert anon_res.status_code == 200
    assert "Sign In" in anon_res.text


def test_login_rate_limiting(client):
    """
    Verify that excessive authentication failures trigger HTTP 429 Too Many Requests.
    """
    bad_payload = {
        "email": "bruteforce@apexcloud.io",
        "password": "WrongPassword!"
    }

    # Send requests up to the allowed limit (5 per minute)
    for _ in range(5):
        resp = client.post(f"{settings.API_V1_STR}/auth/login", json=bad_payload)
        assert resp.status_code == 401

    # 6th request should be blocked by rate limiter
    blocked_resp = client.post(f"{settings.API_V1_STR}/auth/login", json=bad_payload)
    assert blocked_resp.status_code == 429
    assert "Too many requests" in blocked_resp.json()["detail"]
