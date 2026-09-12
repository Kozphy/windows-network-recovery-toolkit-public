"""Privacy risk score tests."""

from __future__ import annotations

from windows_network_toolkit.diagnostics.lan_privacy.models import LanClassification
from windows_network_toolkit.diagnostics.lan_privacy.privacy_risk_score import compute_privacy_risk_score


def test_score_increases_with_probing():
    low = compute_privacy_risk_score(
        observations=[{"protocol": "MDNS", "source_ip": "1.1.1.1", "timestamp_utc": "2026-01-01T00:00:00Z"}],
        devices=[{"ip": "1.1.1.1", "flags": []}],
        classification=LanClassification.NORMAL_DISCOVERY.value,
    )
    high_obs = [
        {
            "protocol": "ICMP",
            "source_ip": "9.9.9.9",
            "target_ip": f"192.168.1.{i}",
            "timestamp_utc": f"2026-01-01T00:0{i}:00Z",
            "evidence_source": "HOST_LEVEL_OBSERVATION",
        }
        for i in range(1, 12)
    ]
    high = compute_privacy_risk_score(
        observations=high_obs,
        devices=[{"ip": "9.9.9.9", "flags": ["unknown_vendor"]}],
        classification=LanClassification.BROAD_SUBNET_PROBING.value,
    )
    assert high.numeric_score > low.numeric_score


def test_evidence_discount_host_only():
    score = compute_privacy_risk_score(
        observations=[{"protocol": "ARP", "source_ip": "1.1.1.1"}],
        devices=[],
        router_events=[],
        classification=LanClassification.INSUFFICIENT_EVIDENCE.value,
    )
    discount = score.components["evidence_confidence_discount"]["score"]
    assert discount > 0
    assert "ROUTER_LEVEL_EVIDENCE" not in score.evidence_sources_present


def test_external_domain_requires_router():
    router = [
        {
            "event_type": "dns",
            "client_ip": "192.168.1.30",
            "domain": "metrics.example-cdn.net",
            "evidence_source": "ROUTER_LEVEL_EVIDENCE",
        }
    ]
    score = compute_privacy_risk_score(
        observations=[],
        devices=[{"ip": "192.168.1.30", "flags": ["iot_like"]}],
        router_events=router,
        classification=LanClassification.NORMAL_DISCOVERY.value,
    )
    assert score.components["external_domain_risk"]["score"] > 0
    assert "ROUTER_LEVEL_EVIDENCE" in score.evidence_sources_present
