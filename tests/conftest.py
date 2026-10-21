import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter


@pytest.fixture(scope="session")
def client():
    """
    Synchronous TestClient fixture for HTTP API testing.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def clean_test_environment(client):
    """
    Ensures test client cookies and login rate limiter are fresh for each test.
    """
    login_rate_limiter.reset()
    client.cookies.clear()
    yield
    login_rate_limiter.reset()
    client.cookies.clear()


@pytest.fixture(scope="session")
def current_settings():
    """
    Access current application settings.
    """
    return settings
