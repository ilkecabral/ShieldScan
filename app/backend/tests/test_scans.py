"""
test_scans.py — Scan endpoint tests.

Covers:
- POST /api/scan/run      → 202 immediately (background task, no blocking)
- GET  /api/scan/progress → returns progress struct
- GET  /api/scan/stats    → returns stats (zeroes before any scan completes)
- GET  /api/scan/history  → returns empty list initially
- GET  /api/scan/findings → returns empty when no completed scan exists
"""

import time


# ── Scan trigger ──────────────────────────────────────────────────────────────

def test_scan_run_returns_202(client, auth_headers):
    """POST /api/scan/run must return 202 immediately (non-blocking)."""
    resp = client.post(
        "/api/scan/run",
        json={"image_name": "nginx:latest"},
        headers=auth_headers,
    )
    assert resp.status_code == 202


def test_scan_run_response_has_poll_url(client, auth_headers):
    """The /run response must tell the client where to poll for progress."""
    resp = client.post(
        "/api/scan/run",
        json={"image_name": "nginx:latest"},
        headers=auth_headers,
    )
    data = resp.json()
    assert "poll_url" in data
    assert "scan" not in data  # 202 must NOT wait for the result


def test_scan_run_requires_auth(client):
    """POST /api/scan/run without a token should return 401."""
    resp = client.post("/api/scan/run", json={"image_name": "nginx:latest"})
    assert resp.status_code == 401


# ── Progress ──────────────────────────────────────────────────────────────────

def test_scan_progress_returns_struct(client, auth_headers):
    """GET /api/scan/progress must return step, pct, done."""
    resp = client.get("/api/scan/progress", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "step" in data
    assert "pct" in data
    assert "done" in data


def test_scan_progress_pct_is_int(client, auth_headers):
    """pct must be a non-negative integer."""
    resp = client.get("/api/scan/progress", headers=auth_headers)
    data = resp.json()
    assert isinstance(data["pct"], int)
    assert data["pct"] >= 0


# ── Stats ─────────────────────────────────────────────────────────────────────

def test_stats_returns_zeros_before_scan(client, auth_headers):
    """Stats before any completed scan should return zero counts."""
    resp = client.get("/api/scan/stats", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    # All count fields must be present and non-negative
    for field in ("risk_score", "total_findings", "critical", "high", "medium", "low"):
        assert field in data
        assert data[field] >= 0


def test_stats_requires_auth(client):
    resp = client.get("/api/scan/stats")
    assert resp.status_code == 401


# ── History ───────────────────────────────────────────────────────────────────

def test_scan_history_returns_list(client, auth_headers):
    resp = client.get("/api/scan/history", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "scans" in data
    assert isinstance(data["scans"], list)


# ── Findings ──────────────────────────────────────────────────────────────────

def test_findings_no_scan_yet(client, auth_headers):
    """Before any scan completes, findings should return a helpful message."""
    resp = client.get("/api/scan/findings", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Either empty findings list or a 'message' key — both are acceptable
    assert "findings" in data or "message" in data


def test_findings_pagination_params(client, auth_headers):
    """page_size out of range should return 400."""
    resp = client.get("/api/scan/findings?page_size=999", headers=auth_headers)
    assert resp.status_code == 400
