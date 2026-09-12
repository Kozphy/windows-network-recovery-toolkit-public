"""Control tests and latest evidence report tests."""

from __future__ import annotations

import json

from windows_network_toolkit.control_tests import ControlTestOutcome, run_endpoint_control_tests
from windows_network_toolkit.latest_evidence_report import (
    build_latest_evidence_package,
    render_latest_evidence_markdown,
)
from windows_network_toolkit.proxy_watch_diagnosis import analyze_proxy_watch_history


def _dead_health_audit() -> dict:
    return {
        "health": {
            "proxy_status": "DIRECT_ONLY_WORKS",
            "tcp_listening": False,
            "direct_probe_ok": True,
            "proxy_probe_ok": False,
        },
        "wininet": {
            "parsed_proxy_server": {"is_localhost_proxy": True, "localhost_port": 59081},
        },
        "evidence": ["Direct ok", "Proxy failed"],
        "limitations": ["test"],
    }


def test_control_health_fail_dead_proxy() -> None:
    state = {
        "wininet_proxy_enabled": True,
        "wininet_proxy_server": "127.0.0.1:59081",
        "winhttp_direct_access": True,
    }
    tests = run_endpoint_control_tests(
        proxy_state=state,
        health_audit=_dead_health_audit(),
        owner={"listener_found": False, "process": None},
    )
    health_ctrl = next(t for t in tests if t.control_id == "WININET_LOCALHOST_PROXY_HEALTH")
    assert health_ctrl.test_result == ControlTestOutcome.FAIL.value
    path_ctrl = next(t for t in tests if t.control_id == "DIRECT_VS_PROXY_PATH_COMPARISON")
    assert path_ctrl.test_result == ControlTestOutcome.FAIL.value


def test_control_health_pass_both_paths() -> None:
    state = {
        "wininet_proxy_enabled": True,
        "wininet_proxy_server": "127.0.0.1:62285",
        "winhttp_direct_access": False,
    }
    audit = {
        "health": {
            "proxy_status": "BOTH_DIRECT_AND_PROXY_WORK",
            "direct_probe_ok": True,
            "proxy_probe_ok": True,
        },
        "wininet": {"parsed_proxy_server": {"is_localhost_proxy": True}},
        "evidence": [],
        "limitations": [],
    }
    owner = {
        "listener_found": True,
        "process": {"name": "node.exe", "pid": 1},
        "localhost_port": 62285,
    }
    tests = run_endpoint_control_tests(proxy_state=state, health_audit=audit, owner=owner)
    assert any(t.control_id == "WININET_LOCALHOST_PROXY_HEALTH" and t.test_result == ControlTestOutcome.PASS.value for t in tests)
    owner_ctrl = next(t for t in tests if t.control_id == "WININET_PROXY_OWNER_VERIFICATION")
    assert owner_ctrl.test_result == ControlTestOutcome.PARTIAL.value


def test_control_reverter_fail() -> None:
    tests = run_endpoint_control_tests(
        proxy_state={"wininet_proxy_enabled": True, "wininet_proxy_server": "127.0.0.1:1"},
        reverter_diagnosis={"status": "REVERTER_SUSPECTED", "evidence": ["cycle"], "limitations": []},
    )
    rev = next(t for t in tests if t.control_id == "PROXY_REVERTER_DETECTION")
    assert rev.test_result == ControlTestOutcome.FAIL.value


def test_control_safe_remediation_pass() -> None:
    tests = run_endpoint_control_tests(proxy_state={"wininet_proxy_enabled": False})
    safe = next(t for t in tests if t.control_id == "SAFE_REMEDIATION_POLICY")
    assert safe.test_result == ControlTestOutcome.PASS.value


def test_control_winhttp_mismatch_fail() -> None:
    tests = run_endpoint_control_tests(
        proxy_state={
            "wininet_proxy_enabled": True,
            "wininet_proxy_server": "127.0.0.1:8080",
            "winhttp_direct_access": True,
        },
    )
    align = next(t for t in tests if t.control_id == "WININET_WINHTTP_ALIGNMENT")
    assert align.test_result == ControlTestOutcome.FAIL.value


def test_repeated_localhost_ports_status() -> None:
    events = [
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62285}},
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62286}},
        {"after": {"wininet_proxy_enabled": 1, "localhost_port": 62287}},
    ]
    diag = analyze_proxy_watch_history(events)
    assert diag.status == "REPEATED_LOCALHOST_PROXY_PORTS"


def test_reverter_same_port_after_disable() -> None:
    events = [
        {
            "before": {"wininet_proxy_enabled": True, "localhost_port": 62285},
            "after": {"wininet_proxy_enabled": False, "localhost_port": 62285},
        },
        {
            "before": {"wininet_proxy_enabled": False, "localhost_port": 62285},
            "after": {"wininet_proxy_enabled": True, "localhost_port": 62285},
        },
    ]
    diag = analyze_proxy_watch_history(events)
    assert diag.status == "REVERTER_SUSPECTED"
    assert any("same localhost port" in e for e in diag.evidence)


def test_latest_evidence_report_fixture_markdown() -> None:
    from pathlib import Path

    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "evidence_report_latest.json").read_text(encoding="utf-8")
    )
    package = build_latest_evidence_package(
        inject_state=fixture["proxy_state"],
        inject_owner=fixture["proxy_owner"],
        inject_health=fixture["health_inject"],
        inject_timeline=fixture["timeline"],
        inject_reverter=fixture["reverter_diagnosis"],
        health_kwargs={"run_direct_probe": False, "run_proxy_probe": False},
    )
    assert len(package["control_tests"]) == 6
    md = render_latest_evidence_markdown(package)
    assert "Control test results" in md
    assert "WININET_LOCALHOST_PROXY_HEALTH" in md
    assert "Safe remediation preview" in md
    json.dumps(package, sort_keys=True)


def test_control_tests_json_serializable() -> None:
    tests = run_endpoint_control_tests(proxy_state={"wininet_proxy_enabled": False})
    payload = [t.to_dict() for t in tests]
    assert json.dumps(payload)
