"""
conftest.py — Shared pytest fixtures for ShieldScan backend tests.

Sets up:
- In-memory SQLite test database (isolated per test session)
- FastAPI TestClient with overridden DB dependency
- Helper to register + log in a test user and return an auth token
"""

import os
import pytest

# Force SQLite in-memory DB before any app imports resolve DATABASE_URL
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_shieldscan.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-at-least-32-characters-long!")
os.environ.setdefault("AWS_ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy0h")  # base64 32 bytes
os.environ.setdefault("ENV", "test")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ..database import Base, get_db
from ..main import app

# ── Test DB setup ─────────────────────────────────────────────────────────────

TEST_DB_URL = "sqlite:///./test_shieldscan.db"

engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    """Create all tables once for the entire test session."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    # Clean up test DB file
    import os as _os
    if _os.path.exists("./test_shieldscan.db"):
        _os.remove("./test_shieldscan.db")


@pytest.fixture(scope="session")
def client(create_tables):
    """FastAPI TestClient with DB dependency overridden to use the test DB."""
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture(scope="session")
def auth_token(client):
    """
    Register a test user and return a valid Bearer token.
    Reused across all tests in the session.
    """
    # Register
    resp = client.post("/api/auth/register", json={
        "email": "test@shieldscan.dev",
        "password": "TestPass1!",
        "full_name": "Test User",
    })
    # 200 = new user, 400 = already exists (re-running tests) — both are fine
    assert resp.status_code in (200, 400), f"Register failed: {resp.text}"

    # Login
    resp = client.post("/api/auth/login", data={
        "username": "test@shieldscan.dev",
        "password": "TestPass1!",
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture
def auth_headers(auth_token):
    """Return Authorization header dict for use in requests."""
    return {"Authorization": f"Bearer {auth_token}"}
