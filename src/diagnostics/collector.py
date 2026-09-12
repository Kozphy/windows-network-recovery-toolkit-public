"""Live Windows probe ingestion for the v1 ``FeatureVector`` (stdlib-only).

Runs read-only subprocess commands (``ping``, ``nslookup``, ``netsh``, ``reg``,
``netstat``, PowerShell probes, ``curl``) and normalizes booleans/counts consumed
by `src.hypothesis.v1_scoring` (import path `src.decision_engine.scoring` shim). Malformed subprocess failures return soft
signals (non-zero codes, empty parses) rather than crashing the collector.

Timezone:
    Probe timestamps are not embedded here; callers stamp artifacts at persist
    time in UTC elsewhere.

Stale / missing data:
    Missing registry keys reduce proxy positives; unreachable gateways yield
    ``gateway_reachable=None`` semantics consistent with scorer checks.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .features import FeatureVector


def run_command(command: list[str], timeout: float = 35.0) -> tuple[int, str]:
    """Run a subprocess and surface failures as `(1, str(exc))` without raising.

    Args:
        command: Argument list passed to ``subprocess.run`` (``shell=False``).
        timeout: Seconds before the process is terminated.

    Returns:
        Exit code plus merged stdout/stderr text.

    Raises:
        None: exceptions convert to synthetic failure tuples for probe stability.
    """
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, output
    except Exception as exc:  # noqa: BLE001 — surface probe failures as soft signals
        return 1, str(exc)


def _winhttp_summary() -> str:
    """Return raw WinHTTP proxy configuration text via ``netsh winhttp show proxy``."""
    _, winhttp = run_command(["netsh", "winhttp", "show", "proxy"])
    return winhttp.strip()


def _winhttp_proxy_enabled(summary: str) -> bool:
    """Infer whether WinHTTP is using a configured proxy versus direct access."""
    return "direct access" not in summary.lower()


def _user_proxy_enabled() -> tuple[bool, list[str]]:
    """True if HKCU hints suggest a manual/auto proxy is in play."""
    reasons: list[str] = []
    code, proxy_enable = run_command(
        [
            "reg",
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
        ]
    )
    if code == 0 and "0x1" in proxy_enable:
        reasons.append("ProxyEnable is set.")

    for key in ("ProxyServer", "AutoConfigURL"):
        cc, _ = run_command(
            [
                "reg",
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                key,
            ]
        )
        if cc == 0:
            reasons.append(f"{key} registry value is present.")

    _, autod = run_command(
        [
            "reg",
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "AutoDetect",
        ]
    )
    if "0x1" in autod:
        reasons.append("AutoDetect is enabled.")

    return (len(reasons) > 0), reasons


def _test_tcp_443() -> bool:
    """Ping TCP 443 to ``www.google.com`` via ``Test-NetConnection`` and parse success."""
    ps = (
        "try { "
        "$t = Test-NetConnection -ComputerName 'www.google.com' -Port 443 "
        "-WarningAction SilentlyContinue -ErrorAction Stop; "
        "$t.TcpTestSucceeded } catch { $false }"
    )
    code, out = run_command(["powershell", "-NoProfile", "-Command", ps], timeout=40.0)
    if code != 0:
        return False
    lines = out.strip().splitlines()
    return "True" in (lines[-1] if lines else "")


def _https_probe() -> tuple[bool, bool]:
    """HEAD ``https://www.google.com`` with curl—return `(https_ok, tls_hint)`.

    The TLS hint activates when stderr/stdout mentions certificate or handshake faults,
    aiding firewall/TLS heuristic scoring without parsing full PEM chains.

    Returns:
        Tuple where the first element is curl success and the second flags TLS keywords.
    """
    code, out = run_command(
        ["curl", "-I", "--max-time", "12", "https://www.google.com"],
        timeout=22.0,
    )
    joined = out.lower()
    tls_hint = any(
        x in joined
        for x in (
            "certificate",
            "ssl_connect",
            "tls",
            "cert verify",
            "unable to get local issuer",
            "handshake failure",
        )
    )
    return code == 0, tls_hint


def probe_https_google() -> tuple[bool, bool]:
    """Public HTTPS HEAD probe for observability modules (curl + TLS keyword hint)."""
    return _https_probe()


def count_in_netstat(keyword: str) -> int:
    """Count ``netstat -an`` lines containing ``keyword`` (case-sensitive substring)."""
    code, out = run_command(["netstat", "-an"])
    if code != 0:
        return 0
    return sum(1 for line in out.splitlines() if keyword in line)


def _default_gateway_ip() -> str | None:
    """Resolve default IPv4 next hop for ``0.0.0.0/0`` using ``Get-NetRoute``."""
    ps = (
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
        "| Sort-Object RouteMetric "
        "| Select-Object -First 1; "
        "if ($r) { $r.NextHop }"
    )
    code, out = run_command(["powershell", "-NoProfile", "-Command", ps], timeout=20.0)
    if code != 0:
        return None
    line = out.strip().splitlines()[-1] if out.strip() else ""
    ip_candidate = line.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_candidate):
        return ip_candidate
    return None


def _physical_adapter_connected() -> bool:
    """Return True when at least one physical adapter reports ``Status=Up``."""
    ps = (
        "$up = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue "
        "| Where-Object { $_.Status -eq 'Up' }); "
        "if ($up.Count -gt 0) { 'true' } else { 'false' }"
    )
    code, out = run_command(["powershell", "-NoProfile", "-Command", ps], timeout=20.0)
    return code == 0 and "true" in out.strip().lower()


def _count_dns_servers_in_ipconfig() -> int:
    """Best-effort count of IPv4 DNS server lines from ``ipconfig /all`` parsing."""
    _, out = run_command(["ipconfig", "/all"], timeout=25.0)
    # Count DNS server IPv4 addresses listed under adapter sections (heuristic).
    count = 0
    for line in out.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("dns servers"):
            remainder = line.split(":", 1)[-1].strip()
            if remainder and remainder.replace(".", "").isdigit():
                count += 1
        elif stripped.startswith("fec0:0:0:ffff::") or re.search(
            r"^\s+\d{1,3}(\.\d{1,3}){3}\s*$", line
        ):
            # Secondary DNS lines are often bare IPv4.
            count += 1
    return max(count, 0)


def _firewall_path_suspected(proxy_summary: str, tcp_ok: bool, https_ok: bool) -> bool:
    """Heuristic: TCP succeeds while HTTPS fails, or proxy text hints filtering."""
    if tcp_ok and not https_ok:
        return True
    if "blocked" in proxy_summary.lower():
        return True
    return False


def collect_features(
    repo_root: Path | None = None,
) -> tuple[FeatureVector, dict[str, Any]]:
    """Collect read-only Windows probe signals and build feature vector.

    Input assumptions:
        - Runs on Windows with required commands available in PATH.
        - Probe failures are treated as signals, not fatal exceptions.

    Output guarantees:
        - Returns normalized `FeatureVector`.
        - Returns metadata with executed command labels/strings.

    Side effects:
        Executes subprocess commands and outbound probe traffic.

    Idempotency:
        Operationally idempotent for stable host/network state.

    Args:
        repo_root: Reserved for future harness integration.

    Returns:
        tuple[FeatureVector, dict[str, Any]]: Feature vector plus metadata.
    """
    del repo_root  # Reserved for scripted offline harnesses.

    executed: list[dict[str, str]] = []

    def _run_logged(cmd: list[str], label: str) -> tuple[int, str]:
        executed.append({"label": label, "cmd": subprocess.list2cmdline(cmd)})
        return run_command(cmd)

    ping_ip_ok = _run_logged(["ping", "-n", "1", "-w", "2000", "8.8.8.8"], "ping_ip")[0] == 0
    ping_domain_ok = _run_logged(["ping", "-n", "1", "-w", "3000", "google.com"], "ping_domain")[
        0
    ] == 0
    nslookup_ok = _run_logged(["nslookup", "google.com"], "nslookup")[0] == 0

    executed.append({"label": "tcp_443", "cmd": "Test-NetConnection ... (PowerShell)"})
    tcp_443_ok = _test_tcp_443()

    executed.append({"label": "browser_http", "cmd": "curl -I https://www.google.com"})
    browser_http_ok, tls_hint = _https_probe()

    winhttp_txt = _winhttp_summary()
    executed.append({"label": "winhttp_proxy", "cmd": subprocess.list2cmdline(["netsh", "winhttp", "show", "proxy"])})
    winhttp_on = _winhttp_proxy_enabled(winhttp_txt)

    executed.append({"label": "hkcu_proxy", "cmd": "reg query HKCU\\\\...\\\\Internet Settings"})
    user_px, _ = _user_proxy_enabled()
    proxy_enabled = winhttp_on or user_px

    dns_servers_detected = _count_dns_servers_in_ipconfig()

    adapter_connected = _physical_adapter_connected()
    gateway_ip = _default_gateway_ip()
    gateway_reachable: bool | None = None
    if gateway_ip:
        gw_code, _ = _run_logged(
            ["ping", "-n", "1", "-w", "2000", gateway_ip],
            "ping_gateway",
        )
        gateway_reachable = gw_code == 0

    tw = count_in_netstat("TIME_WAIT")
    est = count_in_netstat("ESTABLISHED")
    firewall_guess = _firewall_path_suspected(winhttp_txt, tcp_443_ok, browser_http_ok)

    features = FeatureVector(
        ping_ip_ok=ping_ip_ok,
        ping_domain_ok=ping_domain_ok,
        nslookup_ok=nslookup_ok,
        tcp_443_ok=tcp_443_ok,
        browser_http_ok=browser_http_ok,
        proxy_enabled=proxy_enabled,
        winhttp_proxy_enabled=winhttp_on,
        dns_servers_detected=dns_servers_detected,
        adapter_connected=adapter_connected,
        gateway_reachable=gateway_reachable,
        tls_cert_issue_detected=tls_hint,
        firewall_path_suspected=firewall_guess,
        time_wait_count=tw,
        established_count=est,
    )

    meta = {
        "commands_executed": executed,
        "default_gateway_observed": bool(gateway_ip),
    }

    return features, meta


def load_features_json(path: Path) -> FeatureVector:
    """Load feature vector fixture from JSON file.

    Args:
        path: Path to fixture JSON containing either root object fields or a
            nested `features` object.

    Returns:
        FeatureVector: Parsed feature vector.

    Raises:
        ValueError: If JSON root is not an object.
        OSError: If file cannot be read.
        json.JSONDecodeError: If file contents are invalid JSON.
    """
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("fixture root must be an object.")
    root = data.get("features")
    if isinstance(root, dict):
        return FeatureVector.from_dict(root)
    return FeatureVector.from_dict(data)
