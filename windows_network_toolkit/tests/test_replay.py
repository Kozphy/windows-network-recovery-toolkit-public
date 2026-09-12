"""Replay mode tests — non-Windows safe."""

from __future__ import annotations

from pathlib import Path

from windows_network_toolkit.audit.replay import replay_jsonl, replay_to_dict
from windows_network_toolkit.pipeline import run_incident_pipeline

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_replay_proxy_drift_deterministic() -> None:
    path = EXAMPLES / "proxy_drift_incident.jsonl"
    a = replay_to_dict(path)
    b = replay_to_dict(path)
    assert a["incident_type"] == b["incident_type"]
    assert a["confidence"] == b["confidence"]
    assert len(a["timeline"]) == len(b["timeline"])


def test_replay_all_fixtures() -> None:
    for name in (
        "proxy_drift_incident.jsonl",
        "local_proxy_listener.jsonl",
        "dns_ok_browser_fail.jsonl",
        "registry_rewriter_observed.jsonl",
    ):
        result = replay_jsonl(EXAMPLES / name)
        assert result.decision.confidence > 0
        assert result.policy["dry_run"] is True


def test_pipeline_run() -> None:
    result = run_incident_pipeline(
        signals={"wininet_proxy_enabled": True, "proxy_server_localhost": True},
        incident_id="pipe-test",
    )
    assert result.bundle.incident_id == "pipe-test"
    assert result.audit_record["action"] == "pipeline_run"
