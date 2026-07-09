"""
test_health.py — Tests for the /health endpoint.

The health endpoint must:
- Return HTTP 200 when the DB is accessible
- Return JSON with "status" field
- Include "database" key in the response
"""


def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_response_shape(client):
    resp = client.get("/health")
    data = resp.json()
    assert "status" in data
    assert "database" in data


def test_health_database_ok(client):
    resp = client.get("/health")
    data = resp.json()
    # In the test environment the DB is up so status should be "ok" (not "error")
    assert data["database"] == "ok"
