"""API remediation execute dry-run default contract."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.platform_routes import ExecuteIn


def test_execute_in_model_defaults_dry_run_true() -> None:
    body = ExecuteIn(preview_id="preview-1")
    assert body.dry_run is True


@pytest.fixture()
def plat_client(monkeypatch, tmp_path):
    def target():
        return tmp_path

    monkeypatch.setattr("platform_core.storage.platform_data_dir", target)
    monkeypatch.setattr("platform_core.event_bus.platform_data_dir", target)

    from backend.main import app

    return TestClient(
        app,
        headers={"X-Operator-Role": "admin", "X-Operator-Id": "dry-run-contract"},
    )


def test_api_execute_omitting_dry_run_stays_dry_run(plat_client: TestClient, monkeypatch) -> None:
    plat_client.post(
        "/platform/failure-events/ingest",
        json={
            "event_id": "dry-contract-1",
            "endpoint_id": "ep-1",
            "severity": "low",
            "category": "dns",
            "confidence": 0.8,
            "summary": "fixture",
            "recommended_action_key": "reset_dns",
        },
    )
    prv = plat_client.post(
        "/platform/remediation/preview",
        json={
            "endpoint_id": "ep-1",
            "failure_event_id": "dry-contract-1",
            "requested_action": "reset_dns",
        },
    )
    preview_id = prv.json()["preview_id"]

    monkeypatch.setattr(
        "backend.platform_routes.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no subprocess on default dry_run")),
    )

    ex = plat_client.post(
        "/platform/remediation/execute",
        json={"preview_id": preview_id, "confirmation_phrase": "RUN_DNS_RESET"},
    )
    assert ex.status_code == 200
    body = ex.json()
    assert body.get("result") == "dry_run"
    assert body.get("dry_run") is True


def test_platform_health_advertises_dry_run_default(plat_client: TestClient) -> None:
    r = plat_client.get("/platform/health")
    assert r.status_code == 200
    assert r.json().get("remediation_default") == "dry_run"
