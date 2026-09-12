"""Bad-gateway diagnostic tests — mocked, CI-safe."""

from __future__ import annotations

from unittest.mock import MagicMock

from windows_network_toolkit.diagnostics.bad_gateway.classifier import classify_cause, headline
from windows_network_toolkit.diagnostics.bad_gateway.runner import run_bad_gateway_diagnose


def _inject(**overrides: object) -> dict:
    base = {
        "url": "https://example.com/api",
        "dns": {"ok": True, "addresses": ["93.184.216.34"]},
        "tcp": {"ok": True, "host": "example.com", "port": 443},
        "http_system_proxy": {"ok": False, "status_code": 502, "via_system_proxy": True},
        "http_direct": {"ok": True, "status_code": 200, "via_system_proxy": False},
        "wininet_proxy": {"proxy_enable": 1, "proxy_server": "127.0.0.1:8888", "auto_config_url": ""},
        "winhttp_proxy": {"ok": True, "direct_access": False, "raw": ""},
        "local_proxy_process": {"detected": True, "port": 8888, "process": {"pid": 1234, "name": "unknown.exe"}},
    }
    base.update(overrides)
    return base


def test_502_proxy_200_direct_local_loopback() -> None:
    cause, conf, action, notes = classify_cause(_inject())
    assert cause == "LOCAL_LOOPBACK_PROXY"
    assert conf >= 0.75
    assert "CONFIRMATION" in action or "PREVIEW" in action
    assert notes


def test_502_both_paths_remote() -> None:
    probes = _inject(http_direct={"ok": False, "status_code": 502, "via_system_proxy": False})
    cause, _, _, _ = classify_cause(probes)
    assert cause == "REMOTE_UPSTREAM_FAILURE"


def test_dns_failure() -> None:
    cause, _, _, _ = classify_cause(_inject(dns={"ok": False, "addresses": []}))
    assert cause == "DNS_TCP_CONNECTIVITY_ISSUE"


def test_tcp_failure() -> None:
    cause, _, _, _ = classify_cause(_inject(tcp={"ok": False, "host": "x", "port": 443}))
    assert cause == "DNS_TCP_CONNECTIVITY_ISSUE"


def test_runner_mocked_no_subprocess() -> None:
    report = run_bad_gateway_diagnose(
        "https://example.com",
        inject=_inject(),
        run=MagicMock(),
    )
    assert report["classification"] == "LOCAL_LOOPBACK_PROXY"
    assert report["headline"] == headline("LOCAL_LOOPBACK_PROXY")
    assert report["policy_gate"]["outcome"] in {"PREVIEW_ONLY", "BLOCK", "REQUIRE_HUMAN_APPROVAL", "ALLOW"}
    assert "Observation is not proof" in report["safety_notes"][0]


def test_no_destructive_in_recommendation() -> None:
    report = run_bad_gateway_diagnose("https://example.com", inject=_inject(), run=MagicMock())
    action = report["recommended_action"].upper()
    assert "KILL" not in action
    assert "FIREWALL" not in action
    assert "DISABLE" not in action or "CONFIRMATION" in action
