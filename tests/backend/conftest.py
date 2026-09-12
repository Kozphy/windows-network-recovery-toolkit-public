"""Shared fixtures for backend /v1 tests."""

from __future__ import annotations

import pytest

from backend.db import init_trisk_schema, reset_engine
from backend.queue.memory_backend import reset_memory_queue
from backend.trisk_metrics import reset_trisk_metrics
from src.platform_core.events import reset_event_store


@pytest.fixture(autouse=True)
def trisk_test_env(tmp_path, monkeypatch):
    db_path = tmp_path / "trisk.db"
    monkeypatch.setenv("TRISK_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("TRISK_API_TOKEN", "test-token")
    monkeypatch.setenv("TRISK_SYNC_CLASSIFY", "1")
    monkeypatch.setenv("QUEUE_BACKEND", "memory")
    monkeypatch.setenv("PLATFORM_DATA_DIR", str(tmp_path / "platform_data"))
    reset_engine()
    reset_event_store()
    reset_memory_queue()
    reset_trisk_metrics()
    init_trisk_schema()
    yield


@pytest.fixture
def auth_headers():
    return {"X-Api-Token": "test-token", "X-Api-Role": "operator"}


@pytest.fixture
def sample_proxy_evidence():
    return {
        "endpoint_id": "ep-test-001",
        "source_event_id": "src-001",
        "evidence_type": "proxy_state",
        "timestamp_utc": "2026-06-12T10:00:00Z",
        "raw_snapshot": {
            "wininet_proxy_enabled": True,
            "wininet_proxy_server": "127.0.0.1:59081",
            "winhttp_direct_access": True,
            "localhost_port": 59081,
        },
        "normalized_fields": {"wininet_proxy_enabled": True},
        "evidence_tier": "T1_STATE_EVIDENCE",
        "limitations": ["Does not prove malware or MITM."],
    }
