"""Router evidence import and correlation tests."""

from __future__ import annotations

from pathlib import Path

from windows_network_toolkit.diagnostics.router_evidence.correlator import correlate_host_router
from windows_network_toolkit.diagnostics.router_evidence.importers import (
    import_device_list,
    import_dhcp_leases,
    import_dns_log,
    import_firewall_log,
)
from windows_network_toolkit.diagnostics.router_evidence.runner import run_router_import

REPO = Path(__file__).resolve().parents[2]
ROUTER = REPO / "examples" / "router"


def test_import_dns_csv():
    events = import_dns_log(ROUTER / "dns_queries.csv")
    assert len(events) == 3
    assert events[0]["event_type"] == "dns"
    assert events[0]["evidence_source"] == "ROUTER_LEVEL_EVIDENCE"


def test_import_firewall_csv():
    events = import_firewall_log(ROUTER / "firewall_log.csv")
    assert len(events) >= 5
    assert events[0]["src_ip"]


def test_import_dhcp_csv():
    events = import_dhcp_leases(ROUTER / "dhcp_leases.csv")
    assert len(events) == 4
    assert events[0]["mac"]


def test_import_device_list_json():
    events = import_device_list(ROUTER / "device_list.json")
    assert len(events) == 4


def test_router_import_writes_jsonl(tmp_path: Path):
    out = tmp_path / "dns.jsonl"
    result = run_router_import(
        import_type="dns",
        input_path=str(ROUTER / "dns_queries.csv"),
        out_path=str(out),
    )
    assert result["ok"]
    assert out.is_file()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3


def test_correlate_host_router():
    host_obs = [
        {"source_ip": "192.168.1.30", "protocol": "MDNS", "evidence_source": "HOST_LEVEL_OBSERVATION"},
    ]
    router = import_dns_log(ROUTER / "dns_queries.csv")
    devices = [{"ip": "192.168.1.30", "mac": "CC:B1:1A:AA:BB:30", "vendor": "Samsung"}]
    corr = correlate_host_router(host_obs, router, devices)
    assert corr["highest_evidence_source"] == "ROUTER_LEVEL_EVIDENCE"
    assert corr["matched_dns"]
