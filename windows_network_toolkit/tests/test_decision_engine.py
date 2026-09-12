"""Decision engine rule tests."""

from __future__ import annotations

from windows_network_toolkit.decision.decision_model import IncidentType
from windows_network_toolkit.decision.hypothesis_engine import evaluate_incident


def test_wininet_proxy_drift_rule() -> None:
    signals = {
        "wininet_proxy_enabled": True,
        "proxy_server_localhost": "127.0.0.1:56186",
        "wininet_winhttp_divergent": True,
        "browser_https_failed": True,
        "proxy_bypass_succeeded": True,
        "direct_path_success": True,
    }
    decision = evaluate_incident(signals, incident_id="inc-drift")
    assert decision.incident_type in {
        IncidentType.WININET_PROXY_DRIFT,
        IncidentType.PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS,
    }
    assert decision.confidence >= 0.85
    assert decision.requires_confirmation is True
    assert "DISABLE" in decision.recommended_action or "PROXY" in decision.recommended_action


def test_dns_ok_browser_fail() -> None:
    signals = {
        "dns_ok": True,
        "ping_ok": True,
        "browser_https_failed": True,
        "browser_works": False,
    }
    decision = evaluate_incident(signals, incident_id="inc-browser")
    assert decision.incident_type == IncidentType.DNS_OK_BROWSER_FAIL


def test_no_proxy() -> None:
    signals = {"proxy_enable": 0, "wininet_proxy_enabled": False}
    decision = evaluate_incident(signals, incident_id="inc-none")
    assert decision.incident_type == IncidentType.NO_PROXY
