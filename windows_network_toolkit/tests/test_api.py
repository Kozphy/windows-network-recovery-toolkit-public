"""FastAPI route contract tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/health"),
        ("GET", "/platform/status"),
        ("GET", "/platform/evidence/timeline"),
        ("GET", "/platform/decision/latest"),
        ("GET", "/platform/audit/logs"),
        ("POST", "/platform/remediation/preview"),
    ],
)
def test_routes_not_404(method: str, path: str) -> None:
    if method == "GET":
        r = client.get(path)
    else:
        r = client.post(path, json={"action": "disable_wininet_proxy", "evidence_level": "CORRELATED"})
    assert r.status_code != 404, f"{method} {path} returned 404"


def test_health_contract() -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "endpoint-reliability-decision-platform"
    assert "version" in body


def test_diagnose_and_replay() -> None:
    r = client.post(
        "/platform/diagnose",
        json={"fixture_path": "proxy_drift_incident.jsonl", "dry_run": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["dry_run"] is True
    assert "decision" in body

    r2 = client.get("/platform/decision/latest")
    assert r2.status_code == 200
    assert r2.json().get("decision") is not None

    r3 = client.post(
        "/platform/replay",
        json={"fixture_path": "proxy_drift_incident.jsonl", "dry_run": True},
    )
    assert r3.status_code == 200


def test_remediation_confirm_preview_only() -> None:
    r = client.post("/platform/remediation/confirm", json={"dry_run": True})
    assert r.status_code == 200
    assert r.json().get("dry_run") is True


def test_dashboard_static() -> None:
    r = client.get("/dashboard/")
    assert r.status_code == 200
    assert "Endpoint Reliability" in r.text
