"""Localhost proxy health probes — listener ≠ healthy proxy.

Module responsibility:
    Probe TCP listeners and HTTPS paths (direct vs WinINET proxy) to classify proxy health
    status for operators and control tests.

System placement:
    Used by ``proxy-health`` CLI, ``latest_evidence_report``, and ``control_tests``.
    Distinct from malware or EDR inspection — network path evidence only.

Key invariants:
    * ``ProxyStatus`` distinguishes dead proxy, listener-without-proxy, and path outcomes.
    * Read-only — no registry writes or process termination.
    * Timestamps emitted as UTC ISO-8601 strings.

Side effects:
    Network probes when not using inject fixtures; may read registry via supplied state.

Audit Notes:
    * Successful proxy probe does not prove intent or safety of the listener process.
    * Recovery: re-run with ``--fixture`` for deterministic CI/portfolio evidence.
"""

from __future__ import annotations

import http.client
import socket
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from src.proxy_guard.parser import parse_proxy_server

DEFAULT_TEST_URLS = [
    "https://www.msftconnecttest.com/connecttest.txt",
    "https://www.microsoft.com",
    "https://www.google.com/generate_204",
]

ProbeFn = Callable[..., tuple[bool, str]]


class ProxyStatus(StrEnum):
    """Derived health label from TCP listener and HTTPS path probe outcomes.

    ``DEAD_LOCALHOST_PROXY`` and ``DIRECT_ONLY_WORKS`` indicate reliability triage —
    not malware or MITM confirmation.
    """

    HEALTHY_LOCALHOST_PROXY = "HEALTHY_LOCALHOST_PROXY"
    DEAD_LOCALHOST_PROXY = "DEAD_LOCALHOST_PROXY"
    LISTENER_NOT_PROXY = "LISTENER_NOT_PROXY"
    PROXY_FORWARDING_FAILED = "PROXY_FORWARDING_FAILED"
    DIRECT_ONLY_WORKS = "DIRECT_ONLY_WORKS"
    PROXY_ONLY_WORKS = "PROXY_ONLY_WORKS"
    BOTH_DIRECT_AND_PROXY_WORK = "BOTH_DIRECT_AND_PROXY_WORK"
    BOTH_DIRECT_AND_PROXY_FAIL = "BOTH_DIRECT_AND_PROXY_FAIL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    ERROR = "ERROR"


@dataclass
class ProxyHealthResult:
    """Structured localhost proxy health probe result.

    Attributes:
        host: Probe target host (typically loopback).
        port: Configured localhost proxy port.
        timestamp_utc: UTC ISO-8601 probe time.
        tcp_listening: Whether a TCP listener accepts connections on the port.
        proxy_probe_ok: Whether HTTPS via proxy path succeeded.
        direct_probe_ok: Whether direct HTTPS (no proxy) succeeded.
        proxy_status: ``ProxyStatus`` value string summarizing path outcome.
        limitations: Standard attribution and non-accusatory caveats.
    """

    host: str
    port: int
    timestamp_utc: str
    tcp_listening: bool = False
    listener_pid: int | None = None
    listener_name: str | None = None
    listener_path: str | None = None
    listener_command_line: str | None = None
    tcp_connect_ok: bool = False
    proxy_http_ok: bool = False
    proxy_https_connect_ok: bool = False
    external_probe_ok: bool = False
    direct_probe_ok: bool = False
    proxy_probe_ok: bool = False
    proxy_status: str = ProxyStatus.INSUFFICIENT_DATA.value
    failure_reason: str | None = None
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    test_urls_attempted: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return asdict(self)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_limitations() -> list[str]:
    return [
        "Listener ownership is correlation, not registry writer proof.",
        "Registry write attribution requires Sysmon, Procmon, or EventLog evidence.",
        "Successful probe does not prove the proxy is safe or intended.",
    ]


def tcp_connect_probe(host: str, port: int, *, timeout: float = 5.0) -> tuple[bool, str]:
    """Attempt a raw TCP connection to determine whether a listener is present.

    Args:
        host: Target host (typically ``127.0.0.1`` or ``::1``).
        port: Port number to connect to.
        timeout: Socket connect timeout in seconds.

    Returns:
        Tuple of (success, human-readable message). Success means the port is
        accepting TCP connections; it does not prove HTTP proxy behaviour.

    Side effects:
        Opens and immediately closes a TCP socket.

    Audit Notes:
        A successful TCP connect proves a listener exists on the port, not that it
        is a functioning HTTP proxy — see ``proxy_http_probe`` and ``proxy_https_connect_probe``.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP connect to {host}:{port} succeeded"
    except OSError as exc:
        return False, f"TCP connect failed: {exc}"


def direct_https_probe(url: str, *, timeout: float = 5.0) -> tuple[bool, str]:
    """GET a URL directly (bypassing any proxy) to test baseline connectivity.

    Args:
        url: HTTPS URL to probe (e.g. ``https://www.microsoft.com``).
        timeout: Per-request timeout in seconds.

    Returns:
        Tuple of (success, human-readable message). Success means HTTP 2xx–4xx
        response received without proxy routing.

    Side effects:
        Outbound HTTPS request; none when the network is unreachable.

    Audit Notes:
        Direct success while proxy path fails indicates ``DIRECT_ONLY_WORKS`` —
        reliability triage, not MITM confirmation.
    """
    try:
        req = urllib.request.Request(url, method="GET")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            ok = 200 <= int(resp.status) < 500
            return ok, f"Direct GET {url} status={resp.status}"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return False, f"Direct probe failed for {url}: {exc}"


def proxy_http_probe(
    url: str,
    *,
    proxy_host: str,
    proxy_port: int,
    timeout: float = 5.0,
) -> tuple[bool, str]:
    """GET a URL routed through an HTTP proxy to test proxy forwarding.

    Args:
        url: Target URL (HTTP or HTTPS).
        proxy_host: Proxy host (typically ``127.0.0.1`` for localhost tests).
        proxy_port: Proxy port.
        timeout: Per-request timeout in seconds.

    Returns:
        Tuple of (success, human-readable message). Success indicates the proxy
        accepted and forwarded the request.

    Side effects:
        Outbound HTTP/HTTPS request via the configured proxy.

    Audit Notes:
        Success here does not prove the proxy is safe or authorized — it shows
        HTTP forwarding works. Combine with listener attribution for triage.
    """
    proxy_url = f"http://{proxy_host}:{proxy_port}"
    try:
        handlers = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = urllib.request.build_opener(handlers)
        req = urllib.request.Request(url, method="GET")
        with opener.open(req, timeout=timeout) as resp:
            ok = 200 <= int(resp.status) < 500
            return ok, f"Proxy GET via {proxy_url} status={resp.status}"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return False, f"Proxy HTTP probe failed for {url}: {exc}"


def proxy_https_connect_probe(
    url: str,
    *,
    proxy_host: str,
    proxy_port: int,
    timeout: float = 5.0,
) -> tuple[bool, str]:
    """Send an HTTP CONNECT tunnel request to test HTTPS forwarding via the proxy.

    Args:
        url: HTTPS target URL; hostname and port are extracted for the CONNECT header.
        proxy_host: Proxy host for the CONNECT request.
        proxy_port: Proxy port.
        timeout: Socket/request timeout in seconds.

    Returns:
        Tuple of (success, human-readable message). Success (HTTP 200) means the proxy
        accepted the CONNECT tunnel — it does not mean the TLS session was inspected.

    Side effects:
        Opens and closes an HTTP connection to the proxy; does not transmit user data.

    Audit Notes:
        CONNECT 200 confirms the proxy forwards HTTPS tunnels but does not prove TLS
        interception or MITM. Collect Sysmon network events for TLS-path evidence.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False, f"Not an HTTPS URL: {url}"
    target = f"{parsed.hostname}:{parsed.port or 443}"
    try:
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
        conn.request("CONNECT", target, headers={})
        resp = conn.getresponse()
        conn.close()
        ok = resp.status == 200
        return ok, f"CONNECT {target} via proxy status={resp.status}"
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        return False, f"HTTPS CONNECT probe failed: {exc}"


def _derive_proxy_status(
    *,
    tcp_connect_ok: bool,
    tcp_listening: bool,
    proxy_http_ok: bool,
    proxy_https_connect_ok: bool,
    direct_probe_ok: bool,
    external_probe_ok: bool,
    run_direct: bool,
    run_proxy: bool,
) -> tuple[str, str | None]:
    if not tcp_listening and not tcp_connect_ok:
        return (
            ProxyStatus.DEAD_LOCALHOST_PROXY.value,
            "No TCP listener on configured localhost port",
        )

    proxy_any_ok = proxy_http_ok or proxy_https_connect_ok or external_probe_ok

    if run_direct and direct_probe_ok and run_proxy and not proxy_any_ok:
        return (
            ProxyStatus.DIRECT_ONLY_WORKS.value,
            "Direct path works; localhost proxy path failed — likely ERR_PROXY_CONNECTION_FAILED",
        )

    if tcp_connect_ok and run_proxy and not proxy_any_ok:
        if tcp_listening:
            return (
                ProxyStatus.LISTENER_NOT_PROXY.value,
                "Port accepts TCP but HTTP proxy / CONNECT forwarding failed",
            )
        return ProxyStatus.DEAD_LOCALHOST_PROXY.value, "TCP connect failed for configured port"

    if run_proxy and proxy_any_ok and not direct_probe_ok and run_direct:
        return ProxyStatus.PROXY_ONLY_WORKS.value, "Proxy path works; direct path failed"

    if run_direct and direct_probe_ok and proxy_any_ok:
        return ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value, None

    if run_direct and run_proxy and not direct_probe_ok and not proxy_any_ok:
        return ProxyStatus.BOTH_DIRECT_AND_PROXY_FAIL.value, "Both direct and proxy paths failed"

    if proxy_any_ok:
        return ProxyStatus.HEALTHY_LOCALHOST_PROXY.value, None

    if run_proxy and tcp_connect_ok and not proxy_any_ok:
        return (
            ProxyStatus.PROXY_FORWARDING_FAILED.value,
            "Listener present but external forwarding failed",
        )

    return ProxyStatus.INSUFFICIENT_DATA.value, "Insufficient probe data"


def classify_incident_from_health(
    health: ProxyHealthResult,
    *,
    wininet_enabled: bool = True,
    reverter_suspected: bool = False,
    winhttp_mismatch: bool = False,
) -> dict[str, Any]:
    """Map health probe result to incident triage classification.

    Args:
        health: ``ProxyHealthResult`` from ``check_localhost_proxy_health``.
        wininet_enabled: Whether WinINET proxy is currently enabled.
        reverter_suspected: Elevate to ``REVERTER_SUSPECTED`` when flapping detected.
        winhttp_mismatch: Append WinINET/WinHTTP mismatch incident class when applicable.

    Returns:
        Dict with ``incident_class``, ``risk``, ``confidence``, ``recommended_policy_action``,
        and ``human_interpretation``. Reliability triage only — not malware verdict.

    Side effects:
        None.
    """
    status = health.proxy_status
    risk = "MEDIUM"
    incident = "LOCAL_PROXY_ACTIVE"
    policy = "observe_or_alert"
    interpretation = "Localhost proxy health assessed from read-only probes."

    if reverter_suspected:
        incident = "REVERTER_SUSPECTED"
        risk = "HIGH"
        policy = "alert_reverter_suspected"
        interpretation = "Proxy settings flipped without operator confirmation — attribution remains correlational."
    elif status == ProxyStatus.DEAD_LOCALHOST_PROXY.value:
        incident = "DEAD_PROXY_CONFIG"
        risk = "HIGH"
        policy = "block_or_disable_preview"
        interpretation = (
            "Windows points browser traffic to a dead localhost proxy. "
            "This likely causes ERR_PROXY_CONNECTION_FAILED."
        )
    elif status == ProxyStatus.DIRECT_ONLY_WORKS.value:
        incident = "DEAD_PROXY_CONFIG"
        risk = "HIGH"
        policy = "block_or_disable_preview"
        interpretation = "Direct internet works but configured localhost proxy path fails."
    elif status in (
        ProxyStatus.LISTENER_NOT_PROXY.value,
        ProxyStatus.PROXY_FORWARDING_FAILED.value,
    ):
        incident = (
            "LISTENER_NOT_PROXY"
            if status == ProxyStatus.LISTENER_NOT_PROXY.value
            else "PROXY_FORWARDING_FAILED"
        )
        risk = "HIGH"
        policy = "alert_high_risk_proxy_transition"
        interpretation = (
            "A process listens on the port but does not behave as a working HTTP proxy."
        )
    elif status == ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value:
        incident = "LOCAL_PROXY_ACTIVE"
        risk = "LOW"
        policy = "observe_or_alert"
        interpretation = "Localhost proxy is currently functional, but WinINET routing through it may still be unexpected."
    elif status == ProxyStatus.HEALTHY_LOCALHOST_PROXY.value:
        incident = "LOCAL_PROXY_ACTIVE"
        risk = "MEDIUM"
        policy = "observe_or_alert"
        if health.listener_name and health.listener_name.lower() in {"node.exe", "node"}:
            risk = "MEDIUM"
        elif not health.listener_name:
            risk = "HIGH"
        interpretation = f"Localhost proxy forwards traffic; listener appears to be {health.listener_name or 'unknown'}."
    elif status == ProxyStatus.PROXY_ONLY_WORKS.value:
        incident = "LOCAL_PROXY_ACTIVE"
        risk = "MEDIUM"
        policy = "observe_or_alert"
        interpretation = "Direct path failed but proxy path works — possible VPN/tunnel dependency."
    elif status == ProxyStatus.BOTH_DIRECT_AND_PROXY_FAIL.value:
        incident = "DIRECT_CONNECTIVITY_ISSUE"
        risk = "HIGH"
        policy = "investigate_network_path"
        interpretation = "Both direct and proxy paths failed — broader network/TLS issue suspected."
    elif not wininet_enabled:
        incident = "NO_PROXY_DIRECT_OK" if health.direct_probe_ok else "DIRECT_CONNECTIVITY_ISSUE"
        risk = "LOW" if health.direct_probe_ok else "HIGH"
        policy = "observe" if health.direct_probe_ok else "investigate_network_path"

    if winhttp_mismatch and incident not in ("REVERTER_SUSPECTED", "DEAD_PROXY_CONFIG"):
        incident = "WININET_WINHTTP_MISMATCH"

    confidence = 0.55
    if status in (ProxyStatus.DEAD_LOCALHOST_PROXY.value, ProxyStatus.DIRECT_ONLY_WORKS.value):
        confidence = 0.9
    elif status == ProxyStatus.BOTH_DIRECT_AND_PROXY_WORK.value:
        confidence = 0.72
    elif status == ProxyStatus.HEALTHY_LOCALHOST_PROXY.value:
        confidence = 0.7

    return {
        "incident_class": incident,
        "risk": risk,
        "confidence": confidence,
        "recommended_policy_action": policy,
        "human_interpretation": interpretation,
    }


def check_localhost_proxy_health(
    host: str,
    port: int,
    *,
    test_urls: list[str] | None = None,
    timeout_seconds: float = 5.0,
    run_direct_probe: bool = True,
    run_proxy_probe: bool = True,
    listener_info: dict[str, Any] | None = None,
    inject: dict[str, Any] | None = None,
    tcp_probe: ProbeFn | None = None,
    direct_probe: ProbeFn | None = None,
    proxy_probe: ProbeFn | None = None,
    connect_probe: ProbeFn | None = None,
) -> ProxyHealthResult:
    """Run read-only localhost proxy health checks.

    Args:
        host: Loopback or bind address for TCP/proxy probes.
        port: Configured localhost proxy port.
        test_urls: HTTPS URLs for direct and proxied probes; defaults to ``DEFAULT_TEST_URLS``.
        timeout_seconds: Per-probe timeout.
        run_direct_probe: When false, skip direct HTTPS probe.
        run_proxy_probe: When false, skip proxy-path probes.
        listener_info: Optional ``detect_proxy_owner`` dict for listener metadata.
        inject: Fixture dict — returns ``ProxyHealthResult`` without network I/O.
        tcp_probe: Injectable TCP probe callable.
        direct_probe: Injectable direct HTTPS probe callable.
        proxy_probe: Injectable HTTP proxy probe callable.
        connect_probe: Injectable HTTPS CONNECT probe callable.

    Returns:
        ``ProxyHealthResult`` with ``proxy_status``, probe flags, evidence, and limitations.

    Side effects:
        Network probes to configured URLs when not using ``inject``.

    Audit Notes:
        ``DIRECT_ONLY_WORKS`` indicates dead proxy path — reliability triage, not MITM proof.
    """
    if inject:
        data = dict(inject)
        data.setdefault("host", host)
        data.setdefault("port", port)
        data.setdefault("timestamp_utc", _now())
        return ProxyHealthResult(
            **{k: v for k, v in data.items() if k in ProxyHealthResult.__dataclass_fields__}
        )

    urls = list(test_urls or DEFAULT_TEST_URLS)
    evidence: list[str] = []
    limitations = _default_limitations()

    listener = listener_info or {}
    proc = listener.get("process") if isinstance(listener.get("process"), dict) else {}
    listener_pid = proc.get("pid")
    listener_name = proc.get("name")
    listener_path = proc.get("exe_path")
    listener_cmd = proc.get("cmdline")
    tcp_listening = bool(listener.get("listener_found"))

    tcp_fn = tcp_probe or tcp_connect_probe
    direct_fn = direct_probe or direct_https_probe
    proxy_fn = proxy_probe or proxy_http_probe
    connect_fn = connect_probe or proxy_https_connect_probe

    tcp_ok, tcp_msg = tcp_fn(host, port, timeout=timeout_seconds)
    evidence.append(tcp_msg)
    if tcp_listening:
        evidence.append(f"Port {port} has a TCP listener")
        if listener_name:
            evidence.append(f"Listener process appears to be {listener_name} (PID {listener_pid})")
    else:
        evidence.append(f"No listener attributed on port {port}")

    direct_ok = False
    proxy_http_ok = False
    proxy_https_ok = False
    external_ok = False

    if run_direct_probe:
        for url in urls:
            ok, msg = direct_fn(url, timeout=timeout_seconds)
            evidence.append(msg)
            if ok:
                direct_ok = True
                break

    if run_proxy_probe and tcp_ok:
        for url in urls:
            ok_http, msg_http = proxy_fn(
                url,
                proxy_host=host,
                proxy_port=port,
                timeout=timeout_seconds,
            )
            evidence.append(msg_http)
            if ok_http:
                proxy_http_ok = True
                external_ok = True
            if url.startswith("https://"):
                ok_conn, msg_conn = connect_fn(
                    url,
                    proxy_host=host,
                    proxy_port=port,
                    timeout=timeout_seconds,
                )
                evidence.append(msg_conn)
                if ok_conn:
                    proxy_https_ok = True
                    external_ok = True
            if external_ok:
                break

    status, failure = _derive_proxy_status(
        tcp_connect_ok=tcp_ok,
        tcp_listening=tcp_listening,
        proxy_http_ok=proxy_http_ok,
        proxy_https_connect_ok=proxy_https_ok,
        direct_probe_ok=direct_ok,
        external_probe_ok=external_ok,
        run_direct=run_direct_probe,
        run_proxy=run_proxy_probe,
    )

    return ProxyHealthResult(
        host=host,
        port=port,
        timestamp_utc=_now(),
        tcp_listening=tcp_listening,
        listener_pid=listener_pid,
        listener_name=listener_name,
        listener_path=listener_path,
        listener_command_line=listener_cmd,
        tcp_connect_ok=tcp_ok,
        proxy_http_ok=proxy_http_ok,
        proxy_https_connect_ok=proxy_https_ok,
        external_probe_ok=external_ok,
        direct_probe_ok=direct_ok,
        proxy_probe_ok=proxy_http_ok or proxy_https_ok or external_ok,
        proxy_status=status,
        failure_reason=failure,
        evidence=evidence,
        limitations=limitations,
        test_urls_attempted=urls,
    )


def build_proxy_health_audit_payload(
    *,
    wininet: dict[str, Any],
    health: ProxyHealthResult,
    classification: dict[str, Any],
    extra_evidence: list[str] | None = None,
    reverter: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic, audit-friendly JSON payload from health probe results.

    Args:
        wininet: WinINET state dict (keys: ``wininet_proxy_enabled``, ``wininet_proxy_server``, etc.)
            as returned by ``collect_proxy_state_model().to_dict()``.
        health: Completed ``ProxyHealthResult`` from ``check_localhost_proxy_health``.
        classification: Incident classification dict from ``classify_incident_from_health``.
        extra_evidence: Additional evidence strings to append to the evidence list.
        reverter: Optional reverter diagnosis dict; merged under ``reverter_diagnosis`` key.

    Returns:
        Dict with ``event``, ``timestamp_utc``, ``wininet``, ``health``, ``classification``,
        ``evidence``, and ``limitations`` suitable for JSONL append or report embedding.

    Side effects:
        None.

    Audit Notes:
        The returned dict is the canonical audit row for proxy-health events.
        ``limitations`` must not be stripped before governance committee use.
    """
    parsed = parse_proxy_server(wininet.get("wininet_proxy_server"))
    evidence = list(health.evidence) + list(extra_evidence or [])
    if reverter:
        evidence.extend(reverter.get("evidence") or [])

    payload: dict[str, Any] = {
        "event": "proxy_health_check",
        "timestamp_utc": health.timestamp_utc,
        "wininet": {
            "proxy_enable": int(bool(wininet.get("wininet_proxy_enabled"))),
            "proxy_server": wininet.get("wininet_proxy_server"),
            "parsed_proxy_server": {
                "is_localhost_proxy": parsed.is_localhost_proxy,
                "localhost_host": parsed.localhost_host,
                "localhost_port": parsed.localhost_port,
                "proxy_mode": parsed.proxy_mode,
            },
        },
        "health": {
            "proxy_status": health.proxy_status,
            "tcp_listening": health.tcp_listening,
            "listener_pid": health.listener_pid,
            "listener_name": health.listener_name,
            "proxy_https_connect_ok": health.proxy_https_connect_ok,
            "proxy_probe_ok": health.proxy_probe_ok,
            "direct_probe_ok": health.direct_probe_ok,
            "external_probe_ok": health.external_probe_ok,
            "failure_reason": health.failure_reason,
        },
        "classification": classification,
        "evidence": evidence,
        "limitations": health.limitations,
    }
    if reverter:
        payload["reverter_diagnosis"] = reverter
    return payload


def run_proxy_health_for_state(
    state: dict[str, Any],
    owner: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """High-level entry: run health probes from a WinINET state dict and return audit payload.

    Args:
        state: WinINET state dict (``wininet_proxy_enabled``, ``wininet_proxy_server``, etc.)
            from ``collect_proxy_state_model().to_dict()`` or a fixture.
        owner: Optional listener owner dict from ``detect_proxy_owner``; forwarded to probes.
        **kwargs: Forwarded to ``check_localhost_proxy_health`` — supports ``test_urls``,
            ``timeout_seconds``, ``run_direct_probe``, ``run_proxy_probe``, ``reverter_suspected``,
            and injectable probe callables for tests.

    Returns:
        Audit payload dict from ``build_proxy_health_audit_payload`` — includes
        ``health``, ``classification``, ``evidence``, and ``limitations``.

    Side effects:
        TCP and HTTPS network probes when proxy is localhost-configured and ``inject`` is absent.

    Audit Notes:
        When ``wininet_proxy_enabled`` is False or ``ProxyServer`` is non-localhost, returns
        ``INSUFFICIENT_DATA`` with an explanatory ``extra_evidence`` line (no probes run).
    """
    parsed = parse_proxy_server(state.get("wininet_proxy_server"))
    if not state.get("wininet_proxy_enabled"):
        health = ProxyHealthResult(
            host="127.0.0.1",
            port=0,
            timestamp_utc=_now(),
            proxy_status=ProxyStatus.INSUFFICIENT_DATA.value,
            failure_reason="WinINET proxy disabled",
            limitations=_default_limitations(),
        )
        if kwargs.get("run_direct_probe", True):
            direct_ok = False
            for url in kwargs.get("test_urls") or DEFAULT_TEST_URLS:
                ok, msg = (kwargs.get("direct_probe") or direct_https_probe)(
                    url, timeout=kwargs.get("timeout_seconds", 5.0)
                )
                health.evidence.append(msg)
                if ok:
                    direct_ok = True
                    break
            health.direct_probe_ok = direct_ok
            health.proxy_status = (
                ProxyStatus.INSUFFICIENT_DATA.value
                if not direct_ok
                else ProxyStatus.INSUFFICIENT_DATA.value
            )
        classification = classify_incident_from_health(
            health,
            wininet_enabled=False,
            winhttp_mismatch=bool(state.get("winhttp_direct_access") is False),
        )
        return build_proxy_health_audit_payload(
            wininet=state,
            health=health,
            classification=classification,
            extra_evidence=["No localhost proxy health check needed — ProxyEnable=0"],
        )

    if not parsed.is_localhost_proxy or parsed.localhost_port is None:
        health = ProxyHealthResult(
            host=parsed.localhost_host or "127.0.0.1",
            port=parsed.localhost_port or 0,
            timestamp_utc=_now(),
            proxy_status=ProxyStatus.INSUFFICIENT_DATA.value,
            failure_reason="ProxyServer is not a localhost proxy",
            limitations=_default_limitations(),
        )
        classification = classify_incident_from_health(
            health,
            winhttp_mismatch=bool(
                state.get("wininet_proxy_enabled") and state.get("winhttp_direct_access")
            ),
        )
        return build_proxy_health_audit_payload(
            wininet=state,
            health=health,
            classification=classification,
            extra_evidence=["Configured proxy is not localhost — health check skipped"],
        )

    host = parsed.localhost_host or "127.0.0.1"
    port = int(parsed.localhost_port)
    health = check_localhost_proxy_health(
        host,
        port,
        listener_info=owner,
        **kwargs,
    )
    classification = classify_incident_from_health(
        health,
        wininet_enabled=True,
        reverter_suspected=bool(kwargs.get("reverter_suspected")),
        winhttp_mismatch=bool(
            state.get("wininet_proxy_enabled") and state.get("winhttp_direct_access")
        ),
    )
    return build_proxy_health_audit_payload(
        wininet=state, health=health, classification=classification
    )


def format_proxy_health_human(payload: dict[str, Any]) -> str:
    """Format a proxy-health audit payload as a human-readable CLI summary.

    Args:
        payload: Output of ``build_proxy_health_audit_payload`` or ``run_proxy_health_for_state``.

    Returns:
        Multi-line string with WinINET state, TCP listener status, path probe outcomes,
        incident classification, evidence list, and limitations. Suitable for operator
        terminal output and log files.

    Side effects:
        None.
    """
    wininet = payload.get("wininet") or {}
    parsed = wininet.get("parsed_proxy_server") or {}
    health = payload.get("health") or {}
    classification = payload.get("classification") or {}
    lines = [
        "=== Proxy path diagnosis (read-only) ===",
        "",
        "WinINET state:",
        f"  ProxyEnable: {wininet.get('proxy_enable', 0)}",
        f"  ProxyServer: {wininet.get('proxy_server') or '(none)'}",
        f"  Localhost proxy configured: {'yes' if parsed.get('is_localhost_proxy') else 'no'}",
    ]
    if parsed.get("localhost_port"):
        lines.append(f"  Parsed localhost port: {parsed.get('localhost_port')}")
    lines.extend(
        [
            "",
            "TCP / listener:",
            f"  TCP listener attributed: {'yes' if health.get('tcp_listening') else 'no'}",
        ]
    )
    if health.get("listener_name"):
        lines.append(
            f"  Listener process: {health.get('listener_name')} (PID {health.get('listener_pid')})"
        )
    lines.extend(
        [
            "",
            "Path probes:",
            f"  Proxy HTTPS probe: {'ok' if health.get('proxy_probe_ok') else 'failed'}",
            f"  Direct HTTPS probe: {'ok' if health.get('direct_probe_ok') else 'failed'}",
            "",
            f"Classification: {health.get('proxy_status', 'INSUFFICIENT_DATA')}",
            f"Incident class: {classification.get('incident_class', 'N/A')}",
            f"Risk: {classification.get('risk', 'N/A')}",
            f"Recommended policy action: {classification.get('recommended_policy_action', 'observe')}",
        ]
    )
    interp = classification.get("human_interpretation")
    if interp:
        lines.extend(["", f"Interpretation: {interp}"])
    if health.get("failure_reason"):
        lines.append(f"Failure reason: {health.get('failure_reason')}")
    lines.append("")
    lines.append("Evidence:")
    for item in payload.get("evidence") or []:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("Limitations:")
    for item in payload.get("limitations") or []:
        lines.append(f"  - {item}")
    return "\n".join(lines)
