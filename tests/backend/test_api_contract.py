"""API contract tests for /v1 technology-risk routes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def _registered_paths() -> set[str]:
    """Collect route paths across FastAPI flat (pre-0.137) and nested (0.137+) trees."""
    paths: set[str] = set()
    try:
        from fastapi.routing import iter_route_contexts

        for ctx in iter_route_contexts(app.routes):
            path = getattr(ctx, "path", None)
            if isinstance(path, str):
                paths.add(path)
    except ImportError:
        pass
    for r in app.routes:
        path = getattr(r, "path", None)
        if isinstance(path, str):
            paths.add(path)
    # OpenAPI is the stable public contract regardless of route-tree shape
    for path in (app.openapi().get("paths") or {}):
        paths.add(path)
    return paths


def test_v1_routes_registered():
    paths = _registered_paths()
    assert "/v1/evidence" in paths or any(p.startswith("/v1/evidence") for p in paths)
    assert any("incidents" in p for p in paths)


def test_evidence_requires_auth(sample_proxy_evidence):
    r = client.post("/v1/evidence", json=sample_proxy_evidence)
    assert r.status_code == 401


def test_evidence_ingest_contract(sample_proxy_evidence, auth_headers):
    r = client.post("/v1/evidence", json=sample_proxy_evidence, headers=auth_headers)
    assert r.status_code == 202
    body = r.json()
    assert "event_id" in body
    assert "job_id" in body
    assert body["classification_status"] in (
        "pending",
        "classified",
        "review_required",
        "quarantined",
    )


def test_malformed_evidence_400(auth_headers):
    r = client.post(
        "/v1/evidence",
        json={
            "endpoint_id": "x",
            "evidence_type": "proxy_state",
            "timestamp_utc": "2026-06-12T10:00:00Z",
            "raw_snapshot": {},
        },
        headers=auth_headers,
    )
    assert r.status_code == 422 or r.status_code == 400
