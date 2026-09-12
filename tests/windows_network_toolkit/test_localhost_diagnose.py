"""Tests for localhost-diagnose / localhost-watch (inject-first; no external network)."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from windows_network_toolkit.diagnostics.localhost.classifier import classify_localhost_failure
from windows_network_toolkit.diagnostics.localhost.http_probe import (
    HttpProbeResult,
    compare_http_probes,
)
from windows_network_toolkit.diagnostics.localhost.listeners import (
    ListenerDiscoveryResult,
    ListenerRow,
    parse_netstat_listening,
)
from windows_network_toolkit.diagnostics.localhost.remediation import (
    build_remediation_preview,
    policy_envelope,
)
from windows_network_toolkit.diagnostics.localhost.runner import run_localhost_diagnose
from windows_network_toolkit.diagnostics.localhost.target import (
    TargetValidationError,
    parse_localhost_target,
)
from windows_network_toolkit.diagnostics.localhost.tcp_probe import (
    TcpProbeResult,
    categorize_socket_error,
    tcp_probe_address,
)
from windows_network_toolkit.diagnostics.localhost.watch import run_localhost_watch


def test_parse_localhost_url() -> None:
    t = parse_localhost_target(url="http://localhost:61161/ChtPopupForm")
    assert t.host == "localhost"
    assert t.port == 61161
    assert t.path == "/ChtPopupForm"
    assert t.is_loopback


def test_parse_ipv4_and_ipv6_urls() -> None:
    v4 = parse_localhost_target(url="http://127.0.0.1:8080/x")
    assert v4.host == "127.0.0.1" and v4.port == 8080
    v6 = parse_localhost_target(url="http://[::1]:9090/y")
    assert v6.host == "::1" and v6.port == 9090 and v6.is_ipv6_literal


def test_default_http_https_ports() -> None:
    assert parse_localhost_target(url="http://localhost/a").port == 80
    assert parse_localhost_target(url="https://localhost/a").port == 443


def test_invalid_port_and_malformed_url() -> None:
    with pytest.raises(TargetValidationError) as e1:
        parse_localhost_target(host="localhost", port=0)
    assert e1.value.code == "INVALID_PORT"
    with pytest.raises(TargetValidationError) as e2:
        parse_localhost_target(url="ftp://localhost/x")
    assert e2.value.code == "UNSUPPORTED_SCHEME"


def test_non_loopback_rejected() -> None:
    with pytest.raises(TargetValidationError) as exc:
        parse_localhost_target(url="http://example.com:80/")
    assert exc.value.code == "NON_LOOPBACK_TARGET"


def test_conflicting_url_and_host() -> None:
    with pytest.raises(TargetValidationError) as exc:
        parse_localhost_target(url="http://localhost:1/", host="127.0.0.1")
    assert exc.value.code == "CONFLICTING_ARGS"


def test_tcp_success_and_refused() -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        ok = tcp_probe_address("127.0.0.1", port, timeout=1.0)
        assert ok.connect_success and ok.error_category == "CONNECTED"
    finally:
        srv.close()
    # Bind briefly then close without listen to encourage WSAECONNREFUSED on Windows
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    closed_port = holder.getsockname()[1]
    holder.close()
    refused = tcp_probe_address("127.0.0.1", closed_port, timeout=0.5)
    assert not refused.connect_success
    assert refused.error_category in {"CONNECTION_REFUSED", "TIMEOUT"}


def test_tcp_timeout_category() -> None:
    # Non-routable TEST-NET with short timeout — may be TIMEOUT or NETWORK_UNREACHABLE
    result = tcp_probe_address("172.31.255.255", 9, timeout=0.2)
    assert result.error_category in {"TIMEOUT", "NETWORK_UNREACHABLE", "UNKNOWN_SOCKET_ERROR"}


def test_categorize_connection_refused_not_firewall() -> None:
    cat, _code, detail = categorize_socket_error(ConnectionRefusedError(10061, "refused"))
    assert cat == "CONNECTION_REFUSED"
    assert "firewall" not in detail.lower() or "not" in detail.lower()


def _refused_probe(addr: str = "127.0.0.1") -> TcpProbeResult:
    return TcpProbeResult(
        address=addr,
        address_family="IPv6" if ":" in addr else "IPv4",
        port=61161,
        connect_success=False,
        elapsed_ms=1.0,
        error_category="CONNECTION_REFUSED",
        windows_error_code=10061,
        detail="refused",
        timestamp_utc="2026-01-01T00:00:00Z",
    )


def test_classify_no_listener() -> None:
    cls = classify_localhost_failure(
        resolution_errors=[],
        tcp_probes=[_refused_probe("127.0.0.1"), _refused_probe("::1")],
        listeners=ListenerDiscoveryResult(port=61161, listeners=[]),
        http_probes=[],
        proxy=None,
    )
    assert cls.code == "LOCALHOST_SERVICE_NOT_LISTENING"
    assert cls.proof_tier == "T2"
    assert cls.confidence >= 0.9


def test_classify_ipv4_only_mismatch() -> None:
    listeners = ListenerDiscoveryResult(
        port=1,
        listeners=[
            ListenerRow("127.0.0.1", 1, "LISTENING", 10, "IPv4", "loopback", "inject"),
        ],
    )
    tcp = [
        TcpProbeResult("127.0.0.1", "IPv4", 1, True, 1.0, "CONNECTED", None, "ok", "t"),
        TcpProbeResult("::1", "IPv6", 1, False, 1.0, "CONNECTION_REFUSED", 10061, "r", "t"),
    ]
    cls = classify_localhost_failure(
        resolution_errors=[],
        tcp_probes=tcp,
        listeners=listeners,
        http_probes=[],
        proxy=None,
    )
    assert cls.code == "LOCALHOST_IPV4_IPV6_BIND_MISMATCH"


def test_classify_process_exited_requires_prior_evidence() -> None:
    without = classify_localhost_failure(
        resolution_errors=[],
        tcp_probes=[_refused_probe()],
        listeners=ListenerDiscoveryResult(port=1, listeners=[]),
        http_probes=[],
        proxy=None,
        prior_listener_evidence=False,
    )
    assert without.code == "LOCALHOST_SERVICE_NOT_LISTENING"
    with_prior = classify_localhost_failure(
        resolution_errors=[],
        tcp_probes=[_refused_probe()],
        listeners=ListenerDiscoveryResult(port=1, listeners=[]),
        http_probes=[],
        proxy=None,
        prior_listener_evidence=True,
    )
    assert with_prior.code == "LOCALHOST_PROCESS_EXITED_OR_RESTARTED"


def test_classify_port_changed_possible_without_overclaim() -> None:
    cls = classify_localhost_failure(
        resolution_errors=[],
        tcp_probes=[_refused_probe()],
        listeners=ListenerDiscoveryResult(port=1, listeners=[]),
        http_probes=[],
        proxy=None,
        nearby_count=2,
    )
    assert cls.code == "LOCALHOST_PORT_CHANGED_POSSIBLE"
    assert "replacement" in " ".join(cls.limitations).lower() or "nearby" in " ".join(cls.limitations).lower()


def test_proxy_interference_and_unrelated() -> None:
    from windows_network_toolkit.diagnostics.localhost.proxy_evidence import ProxyEvidence

    direct = HttpProbeResult(mode="direct", requested_url="http://127.0.0.1/", success=True, status_code=200)
    proxy = HttpProbeResult(mode="proxy_aware", requested_url="http://127.0.0.1/", success=False, exception_category="CONNECTION_REFUSED")
    cmp = compare_http_probes(direct, proxy)
    assert cmp["differ"] is True
    pe = ProxyEvidence(relation_to_incident="possible_proxy_interference", wininet_enabled=True)
    cls = classify_localhost_failure(
        resolution_errors=[],
        tcp_probes=[
            TcpProbeResult("127.0.0.1", "IPv4", 1, True, 1.0, "CONNECTED", None, "ok", "t"),
        ],
        listeners=ListenerDiscoveryResult(
            port=1,
            listeners=[ListenerRow("127.0.0.1", 1, "LISTENING", 1, "IPv4", "loopback", "inject")],
        ),
        http_probes=[direct, proxy],
        proxy=pe,
    )
    assert cls.code == "LOCALHOST_PROXY_INTERFERENCE"

    both_fail_cmp = compare_http_probes(
        HttpProbeResult(mode="direct", requested_url="u", success=False),
        HttpProbeResult(mode="proxy_aware", requested_url="u", success=False),
    )
    assert "both failed" in both_fail_cmp["interpretation"].lower() or "agree" in both_fail_cmp["interpretation"].lower()


def test_policy_defaults_preview_and_blocks_firewall_proxy() -> None:
    policy = policy_envelope(remediation_requested=True)
    assert policy["decision"] == "PREVIEW"
    assert "firewall_modify" in policy["blocked_automatic_actions"]
    assert "proxy_disable" in policy["blocked_automatic_actions"]
    cls = classify_localhost_failure(
        resolution_errors=[],
        tcp_probes=[_refused_probe(), _refused_probe("::1")],
        listeners=ListenerDiscoveryResult(port=61161, listeners=[]),
        http_probes=[],
        proxy=None,
    )
    items = build_remediation_preview(cls, target_url="http://localhost:61161/ChtPopupForm")
    decisions = {i.action_id: i.policy_decision for i in items}
    assert decisions["block_firewall_change"] == "BLOCK"
    assert decisions["block_auto_proxy_disable"] == "BLOCK"
    assert decisions["block_generic_restart"] == "BLOCK"


def test_netstat_parse_ipv4_ipv6_wildcard() -> None:
    sample = """
  TCP    127.0.0.1:61161        0.0.0.0:0              LISTENING       111
  TCP    [::1]:61161            [::]:0                 LISTENING       111
  TCP    0.0.0.0:61161          0.0.0.0:0              LISTENING       222
  TCP    [::]:61161             [::]:0                 LISTENING       222
"""
    rows = parse_netstat_listening(sample, 61161)
    scopes = {r.binding_scope for r in rows}
    assert "loopback" in scopes and "wildcard" in scopes


def test_listener_disappearing_race_note() -> None:
    from windows_network_toolkit.diagnostics.localhost.listeners import discover_listeners

    calls = {"n": 0}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        class P:
            returncode = 0
            stdout = ""
            stderr = ""

        calls["n"] += 1
        if calls["n"] == 1:
            P.stdout = "  TCP    127.0.0.1:4242        0.0.0.0:0              LISTENING       99\n"
        else:
            P.stdout = ""
        return P()

    result = discover_listeners(4242, run=fake_run, second_pass=True)
    assert result.listeners
    assert result.race_note


def test_process_access_denied_soft_fail() -> None:
    from windows_network_toolkit.diagnostics.localhost.process_info import collect_process_evidence

    ev = collect_process_evidence(
        1,
        inject={
            "process_name": "app.exe",
            "access_denied_fields": ["command_line", "executable_path"],
            "collection_errors": ["Access is denied"],
        },
    )
    assert ev.process_name == "app.exe"
    assert "command_line" in ev.access_denied_fields


def test_runner_inject_no_listener_deterministic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    report = run_localhost_diagnose(
        url="http://localhost:61161/ChtPopupForm",
        inject={
            "resolution": {
                "host": "localhost",
                "ipv4": ["127.0.0.1"],
                "ipv6": ["::1"],
                "has_127_0_0_1": True,
                "has_ipv6_loopback": True,
                "errors": [],
            },
            "tcp_probes": [
                _refused_probe("127.0.0.1").to_dict(),
                _refused_probe("::1").to_dict(),
            ],
            "listeners": [],
            "proxy_evidence": {
                "wininet_enabled": False,
                "relation_to_incident": "proxy_unrelated_to_incident",
                "limitations": [],
            },
        },
        remediation_preview=True,
        evidence_out=tmp_path / "out.json",
    )
    assert report["command"] == "localhost-diagnose"
    assert report["classification"]["code"] == "LOCALHOST_SERVICE_NOT_LISTENING"
    assert report["policy"]["decision"] == "PREVIEW"
    assert report["governance"]
    # Deterministic key ordering not required; stable schema keys yes
    assert set(report["target"]) >= {"url", "host", "port", "path", "is_loopback"}
    audit = tmp_path / "audit" / "localhost-diagnose.jsonl"
    assert audit.is_file()
    row = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert row["classification"] == "LOCALHOST_SERVICE_NOT_LISTENING"
    saved = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert saved["classification"]["code"] == "LOCALHOST_SERVICE_NOT_LISTENING"


def test_cli_localhost_diagnose_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from windows_network_toolkit.cli import main

    fixture = {
        "resolution": {"host": "localhost", "ipv4": ["127.0.0.1"], "ipv6": ["::1"], "errors": []},
        "tcp_probes": [_refused_probe("127.0.0.1").to_dict(), _refused_probe("::1").to_dict()],
        "listeners": [],
        "proxy_evidence": {"wininet_enabled": False, "relation_to_incident": "proxy_unrelated_to_incident"},
    }
    path = tmp_path / "fix.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    rc = main(
        [
            "localhost-diagnose",
            "--url",
            "http://localhost:61161/ChtPopupForm",
            "--fixture",
            str(path),
            "--json",
            "--remediation-preview",
        ]
    )
    assert rc == 0


def test_watch_rejects_aggressive_interval() -> None:
    with pytest.raises(ValueError):
        run_localhost_watch(url="http://127.0.0.1:9/", interval=0.1, duration=1)


def test_integration_temp_http_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    try:
        report = run_localhost_diagnose(
            url=f"http://127.0.0.1:{port}/ChtPopupForm",
            include_http=True,
            timeout=2.0,
            inject={
                # Still use live TCP/HTTP but inject empty proxy to avoid registry
                "proxy_evidence": {
                    "wininet_enabled": False,
                    "relation_to_incident": "proxy_unrelated_to_incident",
                    "limitations": [],
                },
            },
        )
        # Live TCP should connect; listeners may or may not be visible depending on OS timing
        assert any(p["connect_success"] for p in report["tcp_probes"])
        assert report["classification"]["code"] in {
            "LOCALHOST_LISTENER_ACTIVE",
            "LOCALHOST_HTTP_APPLICATION_ERROR",
            "UNKNOWN_LOCALHOST_FAILURE",
        }
    finally:
        server.shutdown()
        server.server_close()
