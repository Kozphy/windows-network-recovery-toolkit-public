"""Unit tests for localhost proxy health and reverter diagnosis."""

from __future__ import annotations

import json

from src.proxy_guard.parser import parse_proxy_server
from windows_network_toolkit.proxy_health import (
    ProxyStatus,
    _derive_proxy_status,
    build_proxy_health_audit_payload,
    check_localhost_proxy_health,
    classify_incident_from_health,
    run_proxy_health_for_state,
)
from windows_network_toolkit.proxy_watch_diagnosis import analyze_proxy_watch_history
from windows_network_toolkit.watch import format_proxy_change_human, run_proxy_watch


def test_parse_localhost_variants() -> None:
    p1 = parse_proxy_server("127.0.0.1:62285")
    assert p1.is_localhost_proxy and p1.localhost_port == 62285

    p2 = parse_proxy_server("localhost:62285")
    assert p2.is_localhost_proxy and p2.localhost_port == 62285

    p3 = parse_proxy_server("http=127.0.0.1:62285;https=127.0.0.1:62285")
    assert p3.is_localhost_proxy and p3.http_localhost_port == 62285

    assert parse_proxy_server("not-a-proxy").is_malformed or not parse_proxy_server("not-a-proxy").is_localhost_proxy
    assert parse_proxy_server("http://pac.example/proxy.pac").proxy_mode != "manual_localhost"


def test_derive_status_dead_no_listener() -> None:
    status, reason = _derive_proxy_status(
        tcp_connect_ok=False,
        tcp_listening=False,
        proxy_http_ok=False,
        proxy_https_connect_ok=False,
        direct_probe_ok=True,
        external_probe_ok=False,
        run_direct=True,
        run_proxy=True,
    )
    assert status == ProxyStatus.DEAD_LOCALHOST_PROXY.value
    assert reason


def test_derive_status_direct_only() -> None:
    status, _ = _derive_proxy_status(
        tcp_connect_ok=True,
        tcp_listening=True,
        proxy_http_ok=False,
        proxy_https_connect_ok=False,
        direct_probe_ok=True,
        external_probe_ok=False,
        run_direct=True,
        run_proxy=True,
    )
    assert status == ProxyStatus.DIRECT_ONLY_WORKS.value


def test_derive_status_both_work() -> None:
    status, failure = _derive_proxy_status(
        tcp_connect_ok=True,
        tcp_listening=True,
        proxy_http_ok=True,
        proxy_https_connect_ok=True,
        direct_probe_ok=True,
        external_probe_ok=True,
        run_direct=True,
        run_proxy=True,
    )
    assert status == ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value
    assert failure is None


def test_derive_status_listener_not_proxy() -> None:
    status, _ = _derive_proxy_status(
        tcp_connect_ok=True,
        tcp_listening=True,
        proxy_http_ok=False,
        proxy_https_connect_ok=False,
        direct_probe_ok=False,
        external_probe_ok=False,
        run_direct=True,
        run_proxy=True,
    )
    assert status == ProxyStatus.LISTENER_NOT_PROXY.value


def test_check_health_inject_dead() -> None:
    result = check_localhost_proxy_health(
        "127.0.0.1",
        62285,
        inject={
            "host": "127.0.0.1",
            "port": 62285,
            "timestamp_utc": "2026-06-12T00:00:00Z",
            "tcp_listening": False,
            "tcp_connect_ok": False,
            "direct_probe_ok": True,
            "proxy_status": ProxyStatus.DEAD_LOCALHOST_PROXY.value,
            "evidence": ["no listener"],
            "limitations": ["test"],
        },
    )
    assert result.proxy_status == ProxyStatus.DEAD_LOCALHOST_PROXY.value
    assert result.direct_probe_ok is True


def test_check_health_inject_healthy() -> None:
    result = check_localhost_proxy_health(
        "127.0.0.1",
        62285,
        inject={
            "host": "127.0.0.1",
            "port": 62285,
            "timestamp_utc": "2026-06-12T00:00:00Z",
            "tcp_listening": True,
            "tcp_connect_ok": True,
            "listener_name": "node.exe",
            "listener_pid": 42,
            "proxy_http_ok": True,
            "proxy_https_connect_ok": True,
            "external_probe_ok": True,
            "direct_probe_ok": True,
            "proxy_status": ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value,
            "evidence": ["ok"],
            "limitations": ["test"],
        },
    )
    assert result.proxy_status == ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value


def test_classify_dead_proxy_config() -> None:
    from windows_network_toolkit.proxy_health import ProxyHealthResult

    health = ProxyHealthResult(
        host="127.0.0.1",
        port=1,
        timestamp_utc="2026-06-12T00:00:00Z",
        proxy_status=ProxyStatus.DIRECT_ONLY_WORKS.value,
        direct_probe_ok=True,
    )
    cls = classify_incident_from_health(health)
    assert cls["incident_class"] == "DEAD_PROXY_CONFIG"
    assert cls["risk"] == "HIGH"


def test_audit_json_serializable() -> None:
    from windows_network_toolkit.proxy_health import ProxyHealthResult

    health = ProxyHealthResult(
        host="127.0.0.1",
        port=62285,
        timestamp_utc="2026-06-12T00:00:00Z",
        proxy_status=ProxyStatus.HEALTHY_LOCALHOST_PROXY.value,
    )
    payload = build_proxy_health_audit_payload(
        wininet={"wininet_proxy_enabled": True, "wininet_proxy_server": "127.0.0.1:62285"},
        health=health,
        classification=classify_incident_from_health(health),
    )
    text = json.dumps(payload, sort_keys=True)
    assert "proxy_health_check" in text


def test_reverter_enable_cycle() -> None:
    events = [
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62285}},
        {"after": {"wininet_proxy_enabled": 0, "localhost_port": 62285}},
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62285}},
    ]
    diag = analyze_proxy_watch_history(events)
    assert diag.status == "REVERTER_SUSPECTED"
    assert diag.enable_disable_cycle_count >= 1


def test_reverter_changing_ports() -> None:
    events = [
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62285}},
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62286}},
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62287}},
    ]
    diag = analyze_proxy_watch_history(events)
    assert diag.status == "REPEATED_LOCALHOST_PROXY_PORTS"


def test_reverter_same_process_correlation() -> None:
    events = [
        {
            "after": {"wininet_proxy_enabled": 1, "localhost_port": 62285},
            "owner": {"process": {"name": "node.exe", "cmdline": "node dev.js"}},
        },
        {
            "after": {"wininet_proxy_enabled": 0},
        },
        {
            "after": {"wininet_proxy_enabled": 1, "localhost_port": 62285},
            "owner": {"process": {"name": "node.exe", "cmdline": "node dev.js"}},
        },
    ]
    diag = analyze_proxy_watch_history(events)
    assert diag.suspected_reverter_process == "node.exe"
    assert "correlation only" in " ".join(diag.limitations).lower()


def test_proxy_watch_fixture_with_health() -> None:
    sequence = [
        {
            "wininet_proxy_enabled": False,
            "wininet_proxy_server": "",
            "wininet_auto_config_url": "",
            "winhttp_direct_access": True,
            "localhost_port": None,
        },
        {
            "wininet_proxy_enabled": True,
            "wininet_proxy_server": "127.0.0.1:62285",
            "wininet_auto_config_url": "",
            "winhttp_direct_access": True,
            "localhost_port": 62285,
        },
    ]
    health_inject = {
        "host": "127.0.0.1",
        "port": 62285,
        "timestamp_utc": "2026-06-12T00:00:00Z",
        "tcp_listening": True,
        "tcp_connect_ok": True,
        "listener_name": "node.exe",
        "listener_pid": 102888,
        "proxy_https_connect_ok": True,
        "direct_probe_ok": True,
        "external_probe_ok": True,
        "proxy_status": ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value,
        "evidence": ["probe ok"],
        "limitations": ["test"],
    }
    payload = run_proxy_watch(
        inject_sequence=sequence,
        health_inject=health_inject,
        run_direct_probe=False,
        run_proxy_probe=False,
    )
    changes = [e for e in payload["events"] if e["event"] == "proxy_change"]
    assert len(changes) == 1
    assert changes[0]["health"]["proxy_status"] == ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value
    assert "health_audit" in changes[0]


def test_format_proxy_change_human() -> None:
    text = format_proxy_change_human(
        {
            "old_state": {"wininet_proxy_server": None, "wininet_proxy_enabled": False},
            "new_state": {"wininet_proxy_server": "127.0.0.1:62285", "wininet_proxy_enabled": True},
            "health_audit": {
                "health": {
                    "proxy_status": "DIRECT_ONLY_WORKS",
                    "tcp_listening": False,
                    "proxy_https_connect_ok": False,
                    "direct_probe_ok": True,
                },
                "classification": {
                    "risk": "HIGH",
                    "human_interpretation": "Dead proxy",
                    "recommended_policy_action": "block_or_disable_preview",
                },
                "evidence": ["Direct works", "Proxy failed"],
            },
        }
    )
    assert "PROXY CHANGE DETECTED" in text
    assert "DIRECT_ONLY_WORKS" in text
    assert "block_or_disable_preview" in text


def test_run_proxy_health_disabled() -> None:
    payload = run_proxy_health_for_state(
        {
            "wininet_proxy_enabled": False,
            "wininet_proxy_server": "",
            "winhttp_direct_access": True,
        },
        None,
        run_direct_probe=False,
        run_proxy_probe=False,
    )
    assert payload["event"] == "proxy_health_check"
    assert "No localhost proxy" in " ".join(payload.get("evidence") or [])


def test_run_proxy_health_non_localhost() -> None:
    payload = run_proxy_health_for_state(
        {
            "wininet_proxy_enabled": True,
            "wininet_proxy_server": "proxy.corp.example:8080",
            "winhttp_direct_access": False,
        },
        None,
        run_direct_probe=False,
        run_proxy_probe=False,
    )
    assert "not localhost" in " ".join(payload.get("evidence") or []).lower()
