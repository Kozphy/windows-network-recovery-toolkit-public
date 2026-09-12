"""Evidence model tests."""

from __future__ import annotations

from windows_network_toolkit.evidence.confidence_score import explain_confidence, ordinal_confidence
from windows_network_toolkit.evidence.evidence_model import EvidenceBundle, EvidenceEvent


def test_evidence_event_validation() -> None:
    ev = EvidenceEvent(
        event_id="e1",
        timestamp="2026-06-09T10:01:00Z",
        source="fixture",
        category="signal",
        signal="PROXY_ENABLED",
        observed_value="ProxyEnable=1",
        severity="medium",
    )
    assert ev.dedupe_key() == ("2026-06-09T10:01:00Z", "PROXY_ENABLED", "ProxyEnable=1")


def test_evidence_bundle_timeline_json() -> None:
    bundle = EvidenceBundle(
        incident_id="inc-1",
        created_at="2026-06-09T10:00:00Z",
        events=[
            EvidenceEvent(
                event_id="e1",
                timestamp="2026-06-09T10:02:00Z",
                source="f",
                category="s",
                signal="LOCAL_PROXY_LISTENER",
                observed_value="127.0.0.1:56186",
                severity="high",
            ),
            EvidenceEvent(
                event_id="e2",
                timestamp="2026-06-09T10:01:00Z",
                source="f",
                category="s",
                signal="PROXY_ENABLED",
                observed_value="ProxyEnable=1",
                severity="medium",
            ),
        ],
    )
    tl = bundle.to_timeline_json()
    assert tl[0]["signal"] == "PROXY_ENABLED"
    assert tl[1]["signal"] == "LOCAL_PROXY_LISTENER"


def test_confidence_explainable() -> None:
    score = ordinal_confidence("high", evidence_level="CORRELATED")
    assert 0.0 < score <= 0.98
    text = explain_confidence("high", evidence_level="CORRELATED", supporting=["proxy_enable"])
    assert "not certainty" in text
