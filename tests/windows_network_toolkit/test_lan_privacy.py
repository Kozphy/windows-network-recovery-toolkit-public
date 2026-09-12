"""Tests for LAN privacy monitor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_network_toolkit.diagnostics.lan_privacy.classifier import classify_lan_behavior
from windows_network_toolkit.diagnostics.lan_privacy.collectors import (
    collect_inventory,
    observations_from_watch_events,
)
from windows_network_toolkit.diagnostics.lan_privacy.models import LanClassification
from windows_network_toolkit.diagnostics.lan_privacy.oui_lookup import lookup_vendor
from windows_network_toolkit.diagnostics.lan_privacy.privacy_risk_score import compute_privacy_risk_score
from windows_network_toolkit.diagnostics.lan_privacy.runner import (
    load_bundle,
    run_lan_risk_score_pipeline,
)
from windows_network_toolkit.diagnostics.lan_privacy.watch import load_watch_jsonl, run_lan_watch

REPO = Path(__file__).resolve().parents[2]
LAN_EXAMPLES = REPO / "examples" / "lan"


def _obs_from_fixture(name: str) -> list[dict]:
    events = load_watch_jsonl(LAN_EXAMPLES / name)
    return observations_from_watch_events(events)


def test_normal_mdns_ssdp_discovery():
    obs = _obs_from_fixture("normal_home_network.jsonl")
    devices = events_devices("normal_home_network.jsonl")
    result = classify_lan_behavior(observations=obs, devices=devices)
    assert result.primary_classification == LanClassification.NORMAL_DISCOVERY.value


def test_smart_tv_frequent_discovery():
    obs = _obs_from_fixture("smart_tv_frequent_discovery.jsonl")
    devices = events_devices("smart_tv_frequent_discovery.jsonl")
    result = classify_lan_behavior(observations=obs, devices=devices)
    assert result.primary_classification == LanClassification.FREQUENT_DISCOVERY.value


def test_repeated_subnet_probing():
    obs = _obs_from_fixture("unknown_broad_probing.jsonl")
    devices = events_devices("unknown_broad_probing.jsonl")
    result = classify_lan_behavior(observations=obs, devices=devices)
    assert result.primary_classification in {
        LanClassification.BROAD_SUBNET_PROBING.value,
        LanClassification.POSSIBLE_LATERAL_RECON.value,
        LanClassification.UNKNOWN_IOT_DEVICE.value,
    }


def test_unknown_iot_vendor():
    devices = [
        {
            "ip": "192.168.1.99",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Unknown",
            "vendor_known": False,
            "flags": ["unknown_vendor"],
        }
    ]
    obs = [
        {
            "timestamp_utc": "2026-06-12T12:00:00Z",
            "protocol": "MDNS",
            "source_ip": "192.168.1.99",
            "evidence_source": "HOST_LEVEL_OBSERVATION",
        },
        {
            "timestamp_utc": "2026-06-12T12:01:00Z",
            "protocol": "SSDP",
            "source_ip": "192.168.1.99",
            "evidence_source": "HOST_LEVEL_OBSERVATION",
        },
        {
            "timestamp_utc": "2026-06-12T12:02:00Z",
            "protocol": "MDNS",
            "source_ip": "192.168.1.99",
            "evidence_source": "HOST_LEVEL_OBSERVATION",
        },
    ]
    result = classify_lan_behavior(observations=obs, devices=devices)
    assert result.primary_classification == LanClassification.UNKNOWN_IOT_DEVICE.value


def test_insufficient_evidence():
    obs = _obs_from_fixture("router_evidence_unavailable.jsonl")
    devices = events_devices("router_evidence_unavailable.jsonl")
    result = classify_lan_behavior(observations=obs, devices=devices)
    assert result.primary_classification == LanClassification.INSUFFICIENT_EVIDENCE.value


def test_risk_score_boundaries():
    score = compute_privacy_risk_score(
        observations=[],
        devices=[],
        router_events=[],
        classification=LanClassification.INSUFFICIENT_EVIDENCE.value,
    )
    assert 0 <= score.numeric_score <= 100
    assert score.risk_level in {"LOW", "MEDIUM", "HIGH"}
    assert score.limitations


def test_lan_watch_fixture_replay():
    data = json.loads((LAN_EXAMPLES / "normal_home_network.jsonl").read_text(encoding="utf-8").splitlines()[0])
    payload = run_lan_watch(duration=1, inject_sequence=[{"devices": data.get("devices", []), "observations": data.get("observations", [])}])
    assert payload["ok"] is True
    assert payload["events"]


def test_inventory_fixture():
    inv = collect_inventory(
        inject={
            "subnet": "192.168.1.0/24",
            "devices": [{"ip": "192.168.1.1", "mac": "00:1D:0F:AA:BB:01", "vendor": "TP-Link", "vendor_known": True, "flags": []}],
        }
    )
    assert inv["ok"]
    assert len(inv["devices"]) == 1


def test_oui_lookup_apple():
    vendor, known = lookup_vendor("3C:22:FB:AA:BB:CC")
    assert known
    assert "Apple" in vendor


def test_executive_bundle_pipeline():
    bundle = load_bundle(LAN_EXAMPLES / "executive_bundle.json")
    result = run_lan_risk_score_pipeline(bundle)
    assert "risk_score" in result
    assert result["risk_score"]["numeric_score"] >= 0


def events_devices(fixture_name: str) -> list[dict]:
    events = load_watch_jsonl(LAN_EXAMPLES / fixture_name)
    if events:
        return events[-1].get("devices") or []
    return []
