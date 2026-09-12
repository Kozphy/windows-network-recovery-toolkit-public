"""Timeline builder tests."""

from __future__ import annotations

from pathlib import Path

from windows_network_toolkit.evidence.timeline_builder import TimelineBuilder

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_timeline_dedup_and_sort() -> None:
    builder = TimelineBuilder(incident_id="inc-test")
    builder.add_signal("PROXY_ENABLED", "ProxyEnable=1", timestamp="2026-06-09T10:01:00Z")
    builder.add_signal("PROXY_ENABLED", "ProxyEnable=1", timestamp="2026-06-09T10:01:00Z")
    builder.add_signal("LOCAL_PROXY_LISTENER", "127.0.0.1:56186", timestamp="2026-06-09T10:02:00Z")
    bundle = builder.build()
    assert len(bundle.events) == 2
    tl = bundle.to_timeline_json()
    assert tl[0]["signal"] == "PROXY_ENABLED"
    assert tl[1]["severity"] == "medium" or tl[1]["signal"] == "LOCAL_PROXY_LISTENER"


def test_ingest_jsonl_fixture() -> None:
    path = EXAMPLES / "proxy_drift_incident.jsonl"
    builder = TimelineBuilder()
    builder.ingest_jsonl(path)
    bundle = builder.build()
    assert len(bundle.events) >= 5
