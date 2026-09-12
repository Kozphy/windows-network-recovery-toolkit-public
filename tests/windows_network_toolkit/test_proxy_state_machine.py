"""Unit and integration tests for proxy state machine (audit-grade classifications)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_network_toolkit.proxy_replay import replay_proxy_events
from windows_network_toolkit.proxy_state_machine import (
    TransitionClass,
    build_proxy_evidence_event,
    classify_transition,
    coalesce_proxy_events,
    detect_reverter_loop_pattern,
)
from windows_network_toolkit.proxy_watch_controls import run_proxy_watch_control_tests
from windows_network_toolkit.watch import run_proxy_watch


def _wininet_state(
    *,
    enabled: int,
    server: str | None,
    timestamp: str | None = None,
    winhttp_direct: bool = False,
) -> dict:
    row = {
        "wininet_proxy_enabled": bool(enabled),
        "wininet_proxy_server": server or "",
        "wininet_auto_config_url": "",
        "winhttp_direct_access": winhttp_direct,
        "localhost_port": 62285 if server and "62285" in server else None,
    }
    if timestamp:
        row["timestamp_utc"] = timestamp
    return row


def test_proxy_server_removed_partial_not_remote() -> None:
    before = _wininet_state(enabled=1, server="127.0.0.1:62285")
    after = _wininet_state(enabled=1, server=None)
    evidence = build_proxy_evidence_event(before_raw=before, after_raw=after, timestamp_utc="2026-01-01T00:00:00Z")
    assert evidence["transition_class"] == TransitionClass.PROXY_SERVER_REMOVED_PARTIAL.value
    assert evidence["risk"] == "LOW"
    assert "REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED" not in json.dumps(evidence)
    assert "not remote proxy configuration" in " ".join(evidence["limitations"]).lower()


def test_proxy_disabled_and_server_removed() -> None:
    before = _wininet_state(enabled=1, server="127.0.0.1:62285")
    after = _wininet_state(enabled=0, server=None)
    evidence = build_proxy_evidence_event(before_raw=before, after_raw=after, timestamp_utc="2026-01-01T00:00:01Z")
    assert evidence["transition_class"] == TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED.value
    assert evidence["risk"] == "LOW"
    assert "proxy disabled and server removed" in evidence["recommended_action"]


def test_localhost_proxy_enabled_correlation_only() -> None:
    before = _wininet_state(enabled=0, server=None)
    after = _wininet_state(enabled=1, server="127.0.0.1:62285")
    listener = {
        "process": {
            "name": "node.exe",
            "pid": 1234,
            "parent": "powershell.exe",
        }
    }
    evidence = build_proxy_evidence_event(
        before_raw=before,
        after_raw=after,
        timestamp_utc="2026-01-01T00:00:02Z",
        listener=listener,
        writer_proof=False,
    )
    assert evidence["transition_class"] == TransitionClass.LOCALHOST_PROXY_ENABLED.value
    assert evidence["proof_tier"] in ("T1", "T2")
    blob = json.dumps(evidence).lower()
    assert "correlation" in blob
    assert evidence["attribution"]["kind"] == "correlation"
    assert evidence["attribution"]["confidence"] < 0.7


def test_remote_proxy_configured_high_risk() -> None:
    before = _wininet_state(enabled=0, server=None)
    after = {
        "wininet_proxy_enabled": True,
        "wininet_proxy_server": "10.0.0.5:8080",
        "wininet_auto_config_url": "",
        "winhttp_direct_access": False,
    }
    evidence = build_proxy_evidence_event(before_raw=before, after_raw=after, timestamp_utc="2026-01-01T00:00:03Z")
    assert evidence["transition_class"] == TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED.value
    assert evidence["risk"] == "HIGH"


def test_reverter_loop_detection() -> None:
    transitions = []
    states = [
        (False, None),
        (True, "127.0.0.1:62285"),
        (False, None),
        (True, "127.0.0.1:62285"),
        (False, None),
        (True, "127.0.0.1:62285"),
    ]
    for i in range(1, len(states)):
        before_enabled, before_server = states[i - 1]
        after_enabled, after_server = states[i]
        before = _wininet_state(enabled=int(before_enabled), server=before_server, winhttp_direct=False)
        after = _wininet_state(enabled=int(after_enabled), server=after_server, winhttp_direct=False)
        ts = f"2026-01-01T00:0{i}:00Z"
        transitions.append(
            build_proxy_evidence_event(
                before_raw=before,
                after_raw=after,
                timestamp_utc=ts,
                listener={"process": {"name": "node.exe", "pid": 1}},
            )
        )

    loop = detect_reverter_loop_pattern(transitions)
    assert loop == TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP
    overlay_action = (
        "require human review — pattern suggests a proxy reverter or auto-reapply loop; "
        "this is correlation, not proof of registry write"
    )
    msg = overlay_action.lower()
    assert "proxy reverter or auto-reapply loop" in msg
    assert "correlation, not proof" in msg


def test_coalesced_disable_merged() -> None:
    before_full = _wininet_state(enabled=1, server="127.0.0.1:62285")
    mid = _wininet_state(enabled=1, server=None)
    after_full = _wininet_state(enabled=0, server=None)
    raw = [
        {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "before": before_full,
            "after": mid,
        },
        {
            "timestamp_utc": "2026-01-01T00:00:00.500Z",
            "before": mid,
            "after": after_full,
        },
    ]
    merged = coalesce_proxy_events(raw, coalesce_window_ms=1000)
    assert len(merged) == 1
    assert merged[0]["coalesced"] is True
    assert merged[0]["raw_sub_event_count"] == 2
    assert merged[0]["transition_class"] == TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED.value
    assert "REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED" not in json.dumps(merged[0])


def test_classify_transition_never_remote_on_empty_after_server() -> None:
    before = {"ProxyEnable": 1, "ProxyServer": "127.0.0.1:62285"}
    after = {"ProxyEnable": 1, "ProxyServer": None}
    assert classify_transition(before, after) == TransitionClass.PROXY_SERVER_REMOVED_PARTIAL


def test_control_classification_accuracy_passes_removal() -> None:
    evidence = build_proxy_evidence_event(
        before_raw=_wininet_state(enabled=1, server="127.0.0.1:62285"),
        after_raw=_wininet_state(enabled=1, server=None),
        timestamp_utc="2026-01-01T00:00:00Z",
    )
    controls = run_proxy_watch_control_tests(events=[evidence])
    acc = next(c for c in controls if c["control_id"] == "CTRL_PROXY_CLASSIFICATION_ACCURACY")
    assert acc["status"] == "PASS"


def test_proxy_replay_fixture(tmp_path: Path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "proxy_loop.jsonl"
    if not fixture.exists():
        pytest.skip("fixture missing")
    rows = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines() if line.strip()]
    payload = replay_proxy_events(rows, coalesce_ms=1000)
    assert payload["summary"]["coalesced_event_count"] >= 1
    assert any(c["control_id"] == "CTRL_AUDIT_REPLAY_DETERMINISM" for c in payload["controls"])


def test_watch_inject_sequence_single_change_still_has_transition_evidence() -> None:
    sequence = [
        {
            "wininet_proxy_enabled": False,
            "wininet_proxy_server": "",
            "wininet_auto_config_url": "",
            "winhttp_direct_access": True,
        },
        {
            "wininet_proxy_enabled": True,
            "wininet_proxy_server": "127.0.0.1:62285",
            "wininet_auto_config_url": "",
            "winhttp_direct_access": False,
            "localhost_port": 62285,
        },
    ]
    payload = run_proxy_watch(
        inject_sequence=sequence,
        coalesce_ms=1000,
        run_direct_probe=False,
        run_proxy_probe=False,
    )
    changes = [e for e in payload["events"] if e.get("event") == "proxy_change"]
    assert len(changes) == 1
    assert changes[0]["transition_evidence"]["transition_class"] == TransitionClass.LOCALHOST_PROXY_ENABLED.value
