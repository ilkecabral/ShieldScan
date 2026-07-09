"""
test_version.py — Version endpoint tests.

Covers:
- GET /api/version              → full version manifest (public, no auth)
- GET /api/version/{component}  → single component version
"""


# ── Full manifest ─────────────────────────────────────────────────────────────

def test_version_returns_200(client):
    """Version endpoint is public — no token needed."""
    resp = client.get("/api/version")
    assert resp.status_code == 200


def test_version_has_app_field(client):
    resp = client.get("/api/version")
    data = resp.json()
    assert "app" in data
    # Should look like a semver string e.g. "1.0.0" or "1.0.0-beta"
    assert "." in data["app"]


def test_version_has_components(client):
    resp = client.get("/api/version")
    data = resp.json()
    assert "components" in data
    components = data["components"]
    # Core components must all be present
    for name in ("api", "cspm", "cwpp", "risk_scorer", "ai_service", "rag", "auth", "frontend"):
        assert name in components, f"Missing component: {name}"


def test_version_has_release_date(client):
    resp = client.get("/api/version")
    data = resp.json()
    assert "release_date" in data
    # Should be an ISO date string e.g. "2026-06-20"
    assert len(data["release_date"]) == 10


# ── Single component ──────────────────────────────────────────────────────────

def test_version_component_cspm(client):
    resp = client.get("/api/version/cspm")
    assert resp.status_code == 200
    data = resp.json()
    assert "version" in data
    assert "." in data["version"]


def test_version_component_unknown(client):
    """Unknown component name should return 404."""
    resp = client.get("/api/version/doesnotexist")
    assert resp.status_code == 404
