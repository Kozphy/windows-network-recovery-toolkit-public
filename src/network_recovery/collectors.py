"""Read-only signal collectors for app-path reliability scenarios.

Module responsibility:
    Gather observation-layer probes (HTTPS curl, DNS, proxy registry, firewall snapshot,
    process detection) into a ``SignalBundle`` without causality claims.

System placement:
    Called by ``engine.run_scenario_diagnosis`` and ``auto_fix`` post-check.

Key invariants:
    * All probes are read-only except subprocess side effects of curl/nslookup/netsh/tasklist.
    * ``bool | None`` fields mean unknown when probe fails (timeout/OSError).
    * Process/listener signals are correlation only (documented in collector_notes).

Side effects:
    Subprocess/network reads only; no registry writes.

Failure modes:
    Individual probe failures yield None or False; bundle still returned with notes.

Input assumptions:
    Windows with curl, nslookup, netsh, tasklist available on PATH.

Output guarantees:
    ``SignalBundle`` JSON-serializable via ``to_dict()``; timestamps not embedded (engine adds UTC).
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from ..proof.proxy_https import _interpret_curl_https_ok, _winhttp_hints_localhost
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.port_listen_probe import localhost_port_listen_state
from ..proxy_guard.registry import read_proxy_registry
from .models import SignalBundle

_CHATGPT_URLS = ("https://chatgpt.com", "https://openai.com")
_BROWSER_URL = "https://www.google.com"
_CURL_URL = "https://www.microsoft.com"
_DNS_HOST = "www.google.com"


def _run_cmd(
    argv: list[str],
    *,
    run: Callable[..., Any],
    timeout: float,
) -> tuple[int, str]:
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        return int(proc.returncode), out.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _curl_ok(url: str, *, run: Callable[..., Any], timeout: float) -> bool | None:
    code, out = _run_cmd(
        ["curl", "-sS", "-o", "NUL", "-w", "%{http_code}", "-L", "--max-time", str(int(timeout)), url],
        run=run,
        timeout=timeout + 5.0,
    )
    return _interpret_curl_https_ok(code, out)


def _dns_ok(*, run: Callable[..., Any], timeout: float) -> bool | None:
    code, _out = _run_cmd(["nslookup", _DNS_HOST], run=run, timeout=timeout)
    return code == 0 if code in (0, 1) else None


def _firewall_snapshot(*, run: Callable[..., Any], timeout: float) -> dict[str, Any]:
    code, out = _run_cmd(
        ["netsh", "advfirewall", "show", "allprofiles", "state"],
        run=run,
        timeout=timeout,
    )
    profiles: dict[str, str] = {}
    current: str | None = None
    if code == 0:
        for line in out.splitlines():
            if line.strip().endswith("Profile Settings:") or line.strip().endswith("Profile Settings"):
                current = line.split()[0].lower() if line.split() else None
            if "State" in line and current:
                profiles[current] = line.strip()
    return {"exit_code": code, "profiles": profiles, "excerpt": out[:1200]}


def _process_detected(image_name: str, *, run: Callable[..., Any], timeout: float) -> bool:
    code, out = _run_cmd(
        ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/FO", "CSV", "/NH"],
        run=run,
        timeout=timeout,
    )
    if code != 0:
        return False
    return image_name.lower() in out.lower()


def _localhost_ports_from_proxy(server: str | None, *, run: Callable[..., Any]) -> tuple[int, ...]:
    parsed = parse_proxy_server(server)
    ports: list[int] = []
    if parsed.localhost_port is not None:
        ports.append(int(parsed.localhost_port))
    for p in (parsed.http_localhost_port, parsed.https_localhost_port, parsed.socks_port):
        if p is not None and int(p) not in ports:
            ports.append(int(p))
    listening: list[int] = []
    for port in ports:
        if localhost_port_listen_state(port, run=run) is True:
            listening.append(port)
    return tuple(listening)


def _vpn_adapter_hint(*, run: Callable[..., Any], timeout: float) -> bool:
    code, out = _run_cmd(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'VPN|TAP|TUN|WireGuard|Wintun' } | Select-Object -First 1 -ExpandProperty Name",
        ],
        run=run,
        timeout=timeout,
    )
    return code == 0 and bool(out.strip())


def collect_signals(
    *,
    run: Callable[..., Any] = subprocess.run,
    timeout_seconds: float = 15.0,
) -> SignalBundle:
    """Gather read-only observations for ChatGPT/desktop-app path scenarios.

    Args:
        run: Subprocess runner (default ``subprocess.run``).
        timeout_seconds: Per-probe timeout budget.

    Returns:
        ``SignalBundle`` with HTTPS/DNS/proxy/process fields; None where probe inconclusive.

    Side effects:
        Invokes curl, nslookup, netsh, tasklist, PowerShell Get-NetAdapter (read-only).
    """
    notes: list[str] = []
    reg = read_proxy_registry(run=run, query_timeout=timeout_seconds)
    parsed = parse_proxy_server(reg.proxy_server)

    wh_code, wh_out = _run_cmd(["netsh", "winhttp", "show", "proxy"], run=run, timeout=timeout_seconds)
    wh_loopback, _wh_port = (
        _winhttp_hints_localhost(wh_out) if wh_code == 0 else (False, None)
    )
    wh_direct = "direct access" in wh_out.lower() if wh_code == 0 else None

    browser_ok = _curl_ok(_BROWSER_URL, run=run, timeout=timeout_seconds)
    chatgpt_ok: bool | None = None
    for url in _CHATGPT_URLS:
        ok = _curl_ok(url, run=run, timeout=timeout_seconds)
        if ok is True:
            chatgpt_ok = True
            break
        if ok is False and chatgpt_ok is None:
            chatgpt_ok = False
    openai_ok = _curl_ok("https://openai.com", run=run, timeout=timeout_seconds)
    curl_ok = _curl_ok(_CURL_URL, run=run, timeout=timeout_seconds)
    dns = _dns_ok(run=run, timeout=timeout_seconds)

    fw = _firewall_snapshot(run=run, timeout=timeout_seconds)
    listen_ports = _localhost_ports_from_proxy(reg.proxy_server, run=run)
    chatgpt_proc = _process_detected("ChatGPT.exe", run=run, timeout=timeout_seconds)
    electron_proc = _process_detected("electron.exe", run=run, timeout=timeout_seconds) or _process_detected(
        "ChatGPT.exe", run=run, timeout=timeout_seconds
    )
    vpn_hint = _vpn_adapter_hint(run=run, timeout=timeout_seconds)

    if reg.proxy_enable == 1 and parsed.is_localhost_proxy:
        notes.append("WinINET loopback proxy segment is enabled.")
    if listen_ports:
        notes.append(f"Localhost listener ports up: {list(listen_ports)}.")
    notes.append("Process detection is correlation only; not registry-writer proof.")

    return SignalBundle(
        browser_https_ok=browser_ok,
        chatgpt_https_ok=chatgpt_ok,
        openai_https_ok=openai_ok,
        curl_https_ok=curl_ok,
        dns_ok=dns,
        wininet_proxy_enable=reg.proxy_enable,
        wininet_proxy_server=reg.proxy_server,
        wininet_auto_config_url=reg.auto_config_url,
        winhttp_direct_access=wh_direct,
        winhttp_loopback_hint=bool(wh_loopback),
        firewall_profiles_snapshot=fw,
        localhost_listener_ports=listen_ports,
        chatgpt_process_detected=chatgpt_proc,
        electron_process_detected=electron_proc,
        vpn_adapter_hint=vpn_hint,
        collector_notes=tuple(notes),
    )
