"""
test_auth.py — Auth endpoint tests: registration, login, token validation.

Covers:
- POST /api/auth/register  → new user, duplicate email rejection
- POST /api/auth/login     → valid creds return token, wrong password rejected
- GET  /api/auth/me        → protected route requires valid Bearer token
"""

import pytest


# ── Registration ──────────────────────────────────────────────────────────────

def test_register_new_user(client):
    """A fresh email address should register successfully."""
    resp = client.post("/api/auth/register", json={
        "email": "newuser@shieldscan.dev",
        "password": "NewUser1!",
        "full_name": "New User",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data


def test_register_duplicate_email(client):
    """Registering the same email twice should return 400."""
    payload = {
        "email": "duplicate@shieldscan.dev",
        "password": "Duplicate1!",
        "full_name": "Dup User",
    }
    client.post("/api/auth/register", json=payload)  # first — succeeds
    resp = client.post("/api/auth/register", json=payload)  # second — must fail
    assert resp.status_code == 400


def test_register_weak_password(client):
    """Passwords that fail the strength check should be rejected."""
    resp = client.post("/api/auth/register", json={
        "email": "weakpass@shieldscan.dev",
        "password": "short",
        "full_name": "Weak Pass",
    })
    assert resp.status_code in (400, 422)


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_valid_credentials(client, auth_token):
    """The shared auth_token fixture proves a valid login works."""
    assert auth_token is not None
    assert len(auth_token) > 20  # real JWT, not an empty string


def test_login_wrong_password(client):
    """Wrong password should return 401."""
    resp = client.post("/api/auth/login", data={
        "username": "test@shieldscan.dev",
        "password": "WrongPass99!",
    })
    assert resp.status_code == 401


def test_login_unknown_email(client):
    """Unknown email should return 401 (same as wrong password — prevents enumeration)."""
    resp = client.post("/api/auth/login", data={
        "username": "nobody@shieldscan.dev",
        "password": "AnyPass1!",
    })
    assert resp.status_code == 401


# ── Protected route ───────────────────────────────────────────────────────────

def test_me_with_valid_token(client, auth_headers):
    """GET /api/auth/me with a valid token should return the user's profile."""
    resp = client.get("/api/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "test@shieldscan.dev"


def test_me_without_token(client):
    """GET /api/auth/me without a token should return 401."""
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_me_with_invalid_token(client):
    """GET /api/auth/me with a garbage token should return 401."""
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer notavalidtoken"})
    assert resp.status_code == 401
