"""LAN control matrix tests."""

from __future__ import annotations

from pathlib import Path

from windows_network_toolkit.diagnostics.lan_privacy.runner import load_bundle, _resolve_observations
from windows_network_toolkit.lan_control_tests import run_lan_control_tests, CONTROL_REGISTRY


def test_control_registry_has_eight_controls():
    assert len(CONTROL_REGISTRY) == 8
    ids = {c.control_id for c in CONTROL_REGISTRY}
    assert ids == {f"CTRL-LAN-{i:03d}" for i in range(1, 9)}


def test_ctrl_lan_007_fails_without_router():
    results = run_lan_control_tests(
        inventory={"devices": [{"ip": "1.1.1.1", "mac": "00:00:00:00:00:01", "flags": []}]},
        observations=[{"protocol": "MDNS"}],
        router_events=[],
        score_result={"primary_classification": "NORMAL_DISCOVERY"},
    )
    by_id = {r.control_id: r for r in results}
    assert by_id["CTRL-LAN-007"].test_result == "FAIL"


def test_ctrl_lan_007_passes_with_router():
    repo = Path(__file__).resolve().parents[2]
    bundle = load_bundle(repo / "examples" / "lan" / "executive_bundle.json")
    observations, inventory, router_events = _resolve_observations(bundle)
    results = run_lan_control_tests(
        inventory=inventory,
        observations=observations,
        router_events=router_events,
        score_result={"primary_classification": "NORMAL_DISCOVERY"},
    )
    by_id = {r.control_id: r for r in results}
    assert by_id["CTRL-LAN-007"].test_result == "PASS"


def test_ctrl_lan_008_fails_on_probing():
    results = run_lan_control_tests(
        inventory={"devices": []},
        observations=[{"protocol": "ICMP"}],
        router_events=[],
        score_result={"primary_classification": "BROAD_SUBNET_PROBING"},
    )
    by_id = {r.control_id: r for r in results}
    assert by_id["CTRL-LAN-008"].test_result == "FAIL"
