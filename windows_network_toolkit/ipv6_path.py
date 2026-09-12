"""IPv6 path blackhole diagnosis and prefer-IPv4 remediation.

Module responsibility:
    Detect when IPv4 HTTPS works but IPv6 reachability to dual-stack destinations
    fails (blackholed IPv6), which commonly makes Edge/tabs keep loading while
    Happy Eyeballs waits on AAAA. One-shot ``investigate`` combines proxy/DNS/Wi-Fi
    context with multi-host dual-stack probes. Preview or apply Microsoft prefer-IPv4
    (``DisabledComponents`` bit ``0x20``) behind dry-run + typed confirmation.

System placement:
    CLI: ``ipv6-path`` (investigate), ``ipv6-path-status``, ``ipv6-prefer-ipv4``,
    ``ipv6-restore-preference`` (clear prefer-IPv4 bit).
    Safety tokens: ``PREFER_IPV4_OVER_IPV6``, ``RESTORE_IPV6_PREFERENCE``.

Key invariants:
    * Diagnose is observation only — not proof of ISP fault.
    * Multi-host probes avoid false ``NETWORK_PATH_DEGRADED`` when one CDN flakes.
    * Remediation defaults to ``dry_run=True``.
    * Live apply requires exact confirmation token, Windows, and elevation.
    * Adapter IPv6 disable remains in ``BLOCKED_ACTIONS`` — never auto-applied.

Side effects:
    * Diagnose/investigate: outbound HTTPS probes; registry/binding/DNS reads.
    * Apply: HKLM ``Tcpip6\\Parameters\\DisabledComponents`` OR with ``0x20``;
      DNS flush; audit JSONL append.

Failure modes:
    Non-Windows → unsupported. Missing elevation → ``needs_elevation`` with command.
    Wrong/missing confirm → ``action_allowed: false``.

Audit Notes:
    What could go wrong: prefer-IPv4 on a host that needs working IPv6.
    Detection: audit row + registry value; verify with ``ipv6-path``.
    Recovery: set ``DisabledComponents`` back to prior value (often ``0``) and reboot.
"""

from __future__ import annotations

import platform
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, DEFAULT_SAFETY_NOTES, is_demo_mode

CONFIRMATION_PHRASE = CONFIRMATION_TOKENS.get("PREFER_IPV4_OVER_IPV6", "PREFER_IPV4_OVER_IPV6")
RESTORE_CONFIRMATION_PHRASE = CONFIRMATION_TOKENS.get(
    "RESTORE_IPV6_PREFERENCE", "RESTORE_IPV6_PREFERENCE"
)
PREFER_IPV4_BIT = 0x20
DEFAULT_PROBE_HOST = "www.microsoft.com"
DEFAULT_PROBE_URL = f"https://{DEFAULT_PROBE_HOST}/"
# Ordered fallbacks: intermittent CDN/IPv4 timeouts must not mask blackhole pattern.
DEFAULT_PROBE_URLS: tuple[str, ...] = (
    "https://www.microsoft.com/",
    "https://www.cloudflare.com/",
    "https://www.google.com/generate_204",
    "https://www.bing.com/",
)
TCPIP6_PARAMETERS = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
ELEVATED_APPLY_HINT = (
    "python -m windows_network_toolkit ipv6-prefer-ipv4 "
    "--dry-run false --confirm PREFER_IPV4_OVER_IPV6"
)
ELEVATED_RESTORE_HINT = (
    "python -m windows_network_toolkit ipv6-restore-preference "
    "--dry-run false --confirm RESTORE_IPV6_PREFERENCE"
)


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unsupported() -> dict[str, Any]:
    return {
        "unsupported_platform": True,
        "platform": platform.system(),
        "message": "ipv6-path commands require Windows.",
        "limitations": list(DEFAULT_SAFETY_NOTES),
    }


def is_process_elevated() -> bool | None:
    """Return whether this process has admin elevation (Windows), else None."""
    if platform.system() != "Windows":
        return None
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def read_disabled_components() -> int | None:
    """Read HKLM Tcpip6 DisabledComponents DWORD, or None if missing/unreadable."""
    if platform.system() != "Windows":
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, TCPIP6_PARAMETERS, 0, winreg.KEY_READ
        ) as key:
            value, _ = winreg.QueryValueEx(key, "DisabledComponents")
            return int(value)
    except OSError:
        return None


def write_disabled_components(value: int) -> None:
    """Write HKLM Tcpip6 ``DisabledComponents`` DWORD.

    Args:
        value: Full DWORD to persist (callers must OR/AND bits themselves).

    Raises:
        OSError: Access denied without elevation, or key create/set failure.

    Side effects:
        Mutates HKLM; requires Administrator. Does not reboot the host.

    Audit Notes:
        Callers must gate with dry-run + typed confirmation before invoking.
    """
    import winreg

    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE,
        TCPIP6_PARAMETERS,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "DisabledComponents", 0, winreg.REG_DWORD, int(value))


def wifi_ipv6_binding_enabled(run: Callable[..., Any] | None = None) -> bool | None:
    """Return whether the Wi-Fi adapter has IPv6 (ms_tcpip6) enabled, if discoverable."""
    if platform.system() != "Windows":
        return None
    run_fn = run or subprocess.run
    try:
        completed = run_fn(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetAdapterBinding -Name 'Wi-Fi' -ComponentID ms_tcpip6 "
                "-ErrorAction SilentlyContinue).Enabled",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        text = (completed.stdout or "").strip().lower()
        if text in {"true", "false"}:
            return text == "true"
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def collect_network_context(run: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Collect light Wi-Fi / DNS / proxy / IPv6 addressing context (read-only).

    Args:
        run: Injectable subprocess runner for PowerShell probes.

    Returns:
        Dict with ``wifi_status``, ``wifi_ipv4``, ``has_global_ipv6``,
        ``dns_servers_ipv4``, ``default_gateway_ipv4``, ``wininet_proxy_enable``,
        and ``errors`` (soft-fail list). Missing fields stay ``None`` / empty.

    Side effects:
        Reads HKCU WinINET ``ProxyEnable``; runs PowerShell Get-Net* cmdlets.
        No mutations.

    Failure modes:
        Non-Windows → ``errors`` includes ``network_context_requires_windows``.
        Soft-fails leave partial context rather than raising.
    """
    ctx: dict[str, Any] = {
        "wifi_status": None,
        "wifi_ipv4": None,
        "has_global_ipv6": None,
        "dns_servers_ipv4": [],
        "default_gateway_ipv4": None,
        "wininet_proxy_enable": None,
        "errors": [],
    }
    if platform.system() != "Windows":
        ctx["errors"].append("network_context_requires_windows")
        return ctx

    run_fn = run or subprocess.run
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_READ,
        ) as key:
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            ctx["wininet_proxy_enable"] = int(enable)
    except OSError as exc:
        ctx["errors"].append(f"proxy_read:{exc}"[:160])

    ps = (
        "$a=Get-NetAdapter -Name 'Wi-Fi' -ErrorAction SilentlyContinue; "
        "if($a){$a.Status}else{'missing'}; "
        "Write-Output '---'; "
        "(Get-NetIPAddress -InterfaceAlias 'Wi-Fi' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress); "
        "Write-Output '---'; "
        "[bool](Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -notlike '::1' }); "
        "Write-Output '---'; "
        "((Get-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue).ServerAddresses) -join ','; "
        "Write-Output '---'; "
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Select-Object -First 1 -ExpandProperty NextHop)"
    )
    try:
        completed = run_fn(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        parts = (completed.stdout or "").split("---")
        if len(parts) >= 5:
            ctx["wifi_status"] = parts[0].strip() or None
            ctx["wifi_ipv4"] = parts[1].strip() or None
            glob6 = parts[2].strip().lower()
            ctx["has_global_ipv6"] = (
                True if glob6 == "true" else False if glob6 == "false" else None
            )
            dns = parts[3].strip()
            ctx["dns_servers_ipv4"] = [d.strip() for d in dns.split(",") if d.strip()]
            ctx["default_gateway_ipv4"] = parts[4].strip() or None
    except (OSError, subprocess.SubprocessError) as exc:
        ctx["errors"].append(f"net_ps:{exc}"[:160])
    return ctx


def probe_https_family(
    url: str,
    *,
    family: socket.AddressFamily,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Attempt HTTPS GET forced to one address family via custom opener."""
    label = "ipv4" if family == socket.AF_INET else "ipv6"
    try:
        host = urllib.parse.urlparse(url).hostname or DEFAULT_PROBE_HOST
        infos = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
        if not infos:
            return {"ok": False, "family": label, "error": "no_addresses", "status": None}

        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator probe
            status = getattr(resp, "status", None) or resp.getcode()
            return {"ok": 200 <= int(status) < 400, "family": label, "status": int(status)}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "family": label, "error": str(exc)[:240], "status": None}


def probe_with_curl(
    url: str,
    *,
    ipv4: bool,
    timeout: float = 8.0,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Probe HTTPS with curl ``-4`` or ``-6`` (family forcing on Windows).

    Args:
        url: Absolute HTTPS URL.
        ipv4: When True use ``curl -4``; otherwise ``curl -6``.
        timeout: Max-time seconds passed to curl.
        run: Injectable subprocess runner (tests).

    Returns:
        Dict with ``ok``, ``family``, ``status``, ``url``, and optional ``error``.
        ``ok`` is True when curl exit 0 and HTTP status code ``>= 200`` (reachable
        non-2xx such as 400 still count as path-ok).

    Side effects:
        Spawns ``curl.exe``; may perform outbound HTTPS.

    Failure modes:
        Missing curl, DNS failure (exit 6), timeout (exit 28) → ``ok=False``.
    """
    run_fn = run or subprocess.run
    flag = "-4" if ipv4 else "-6"
    label = "ipv4" if ipv4 else "ipv6"
    try:
        completed = run_fn(
            [
                "curl.exe",
                flag,
                "-s",
                "-o",
                "NUL",
                "-w",
                "%{http_code}",
                "--max-time",
                str(int(timeout)),
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
        code_raw = (completed.stdout or "").strip()
        try:
            code = int(code_raw)
        except ValueError:
            code = 0
        # Treat HTTP 2xx–3xx and common reachable non-2xx (e.g. 400) as path-ok.
        ok = completed.returncode == 0 and code >= 200
        return {
            "ok": ok,
            "family": label,
            "status": code or None,
            "url": url,
            "error": None if ok else f"curl_exit={completed.returncode} code={code_raw}",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "ok": False,
            "family": label,
            "status": None,
            "url": url,
            "error": str(exc)[:240],
        }


def probe_dual_stack_multi(
    *,
    probe_urls: tuple[str, ...] | list[str] = DEFAULT_PROBE_URLS,
    timeout: float = 8.0,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Probe multiple hosts until IPv4 succeeds (and separately until IPv6 succeeds).

    Decision intent:
        Avoid classifying ``NETWORK_PATH_DEGRADED`` when a single dual-stack CDN
        times out on IPv4 while other IPv4 paths work and IPv6 still fails.

    Args:
        probe_urls: Ordered HTTPS URLs; first success per family wins.
        timeout: Per-probe timeout seconds.
        run: Injectable subprocess runner.

    Returns:
        Dict with ``ipv4_probe``, ``ipv6_probe``, ``ipv4_attempts``,
        ``ipv6_attempts``, and ``probe_urls``.

    Side effects:
        Multiple outbound curl probes (stops early per family on success).

    Engineering Notes:
        Sequential fallbacks trade latency for fewer false ``NETWORK_PATH_DEGRADED``
        labels on flaky CDNs — preferred over single-host diagnose for operators.
    """
    urls = list(probe_urls) or [DEFAULT_PROBE_URL]
    attempts_v4: list[dict[str, Any]] = []
    attempts_v6: list[dict[str, Any]] = []
    best_v4: dict[str, Any] | None = None
    best_v6: dict[str, Any] | None = None

    for url in urls:
        result = probe_with_curl(url, ipv4=True, timeout=timeout, run=run)
        attempts_v4.append(result)
        if result.get("ok"):
            best_v4 = result
            break
        if best_v4 is None:
            best_v4 = result

    for url in urls:
        result = probe_with_curl(url, ipv4=False, timeout=timeout, run=run)
        attempts_v6.append(result)
        if result.get("ok"):
            best_v6 = result
            break
        if best_v6 is None:
            best_v6 = result

    assert best_v4 is not None and best_v6 is not None
    return {
        "ipv4_probe": best_v4,
        "ipv6_probe": best_v6,
        "ipv4_attempts": attempts_v4,
        "ipv6_attempts": attempts_v6,
        "probe_urls": urls,
    }


def classify_ipv6_path(
    *,
    ipv4_ok: bool,
    ipv6_ok: bool,
    prefer_ipv4_enabled: bool,
    has_global_ipv6: bool | None = None,
) -> dict[str, Any]:
    """Classify dual-stack path health from probe outcomes.

    Decision intent:
        Answer whether Edge-style hangs are consistent with blackholed IPv6 while
        IPv4 still works (Happy Eyeballs stall on AAAA).

    Args:
        ipv4_ok: True when at least one IPv4 HTTPS probe succeeded.
        ipv6_ok: True when at least one IPv6 HTTPS probe succeeded.
        prefer_ipv4_enabled: True when ``DisabledComponents & 0x20`` is set.
        has_global_ipv6: Optional host addressing hint; ``False`` strengthens
            blackhole reasoning when DNS may still return AAAA.

    Returns:
        Dict with ``primary_classification``, ``severity``, ordinal ``confidence``,
        ``reasoning``, ``recommended_next_actions``, and ``limitations``.

    Side effects:
        None — pure classification from boolean inputs.

    Constraints:
        Observation only — not ISP fault proof. Prefer-IPv4 is a host mitigation.

    Verification:
        ``tests/windows_network_toolkit/test_ipv6_path.py``.
    """
    limitations = [
        "IPv4-ok + IPv6-fail is correlation with Edge hang, not proof of a single root cause.",
        "ISP/router IPv6 repair is the long-term network fix; prefer-IPv4 is a host mitigation.",
        *DEFAULT_SAFETY_NOTES,
    ]
    if ipv4_ok and not ipv6_ok:
        actions = [
            "One-shot: python -m windows_network_toolkit ipv6-path",
            "Preview: python -m windows_network_toolkit ipv6-path --prefer-ipv4 --dry-run true",
            f"Apply elevated: {ELEVATED_APPLY_HINT}",
            "Reboot after DisabledComponents change so Edge reloads the stack.",
            "Optional manual escalation: Disable-NetAdapterBinding -Name Wi-Fi -ComponentID ms_tcpip6",
        ]
        if prefer_ipv4_enabled:
            actions.insert(
                0,
                "Prefer-IPv4 bit already set — reboot OS, or escalate to Wi-Fi IPv6 binding disable.",
            )
        reasoning = (
            "IPv4 HTTPS succeeded and IPv6 reachability failed — dual-stack clients "
            "may stall on AAAA before falling back."
        )
        if has_global_ipv6 is False:
            reasoning += " Host has no global IPv6 address while DNS may still return AAAA."
        return {
            "primary_classification": "IPV6_PATH_BLACKHOLE",
            "severity": "medium",
            "confidence": 0.85 if not prefer_ipv4_enabled else 0.7,
            "reasoning": reasoning,
            "recommended_next_actions": actions,
            "limitations": limitations,
        }
    if ipv4_ok and ipv6_ok:
        return {
            "primary_classification": "IPV6_PATH_OK",
            "severity": "info",
            "confidence": 0.8,
            "reasoning": "Both IPv4 and IPv6 probes succeeded across probe set.",
            "recommended_next_actions": [
                "If Edge still hangs, investigate extensions/GPU/profile — not IPv6 path.",
            ],
            "limitations": limitations,
        }
    if not ipv4_ok and not ipv6_ok:
        return {
            "primary_classification": "NETWORK_PATH_DEGRADED",
            "severity": "high",
            "confidence": 0.75,
            "reasoning": "Both IPv4 and IPv6 HTTPS probes failed across fallback hosts.",
            "recommended_next_actions": [
                "Run: python -m windows_network_toolkit ipv6-path",
                "Check Wi-Fi/DNS/proxy with proxy-status and proxy-health.",
            ],
            "limitations": limitations,
        }
    return {
        "primary_classification": "IPV4_PATH_FAILED_IPV6_OK",
        "severity": "medium",
        "confidence": 0.7,
        "reasoning": "IPv6 worked but IPv4 failed — prefer-IPv4 remediation is not indicated.",
        "recommended_next_actions": ["Investigate IPv4 routing/DNS separately."],
        "limitations": limitations,
    }


def _operator_next_step(
    *,
    classification: str,
    prefer_ipv4_enabled: bool,
    proxy_enable: int | None,
    elevated: bool | None,
) -> dict[str, Any]:
    """Structured next action so operators need no re-prompt."""
    if proxy_enable == 1:
        return {
            "kind": "check_proxy",
            "command": "python -m windows_network_toolkit proxy-status",
            "reason": "WinINET proxy is enabled — resolve proxy health before prefer-IPv4.",
        }
    if classification == "IPV6_PATH_BLACKHOLE":
        if prefer_ipv4_enabled:
            return {
                "kind": "reboot",
                "command": None,
                "reason": "Prefer-IPv4 already set; reboot so Edge/OS reload the stack.",
            }
        if elevated is False:
            return {
                "kind": "prefer_ipv4_apply_elevated",
                "command": ELEVATED_APPLY_HINT,
                "reason": "Blackhole pattern observed; live apply needs an elevated shell.",
            }
        return {
            "kind": "prefer_ipv4_preview",
            "command": ("python -m windows_network_toolkit ipv6-path --prefer-ipv4 --dry-run true"),
            "reason": "Blackhole pattern observed; preview prefer-IPv4, then apply elevated.",
        }
    if classification == "NETWORK_PATH_DEGRADED":
        return {
            "kind": "check_connectivity",
            "command": "python -m windows_network_toolkit proxy-health",
            "reason": "Both address families failed — fix basic connectivity first.",
        }
    return {
        "kind": "observe",
        "command": None,
        "reason": "No prefer-IPv4 action indicated from current evidence.",
    }


def diagnose_ipv6_path(
    *,
    probe_url: str | None = None,
    probe_urls: tuple[str, ...] | list[str] | None = None,
    timeout: float = 8.0,
    run: Callable[..., Any] | None = None,
    ipv4_probe: dict[str, Any] | None = None,
    ipv6_probe: dict[str, Any] | None = None,
    disabled_components: int | None = None,
    wifi_ipv6_enabled: bool | None = None,
    has_global_ipv6: bool | None = None,
    use_fallbacks: bool = True,
) -> dict[str, Any]:
    """Read-only dual-stack path diagnosis (multi-host by default; fixture-injectable).

    Args:
        probe_url: Optional primary HTTPS URL; prepended ahead of default fallbacks
            when ``use_fallbacks`` is True.
        probe_urls: Explicit ordered URL list (overrides default set).
        timeout: Per-probe timeout seconds.
        run: Injectable subprocess runner.
        ipv4_probe / ipv6_probe: Injected probe results for deterministic tests.
        disabled_components: Injected HKLM DWORD (skip live registry read).
        wifi_ipv6_enabled: Injected Wi-Fi ``ms_tcpip6`` binding state.
        has_global_ipv6: Optional addressing hint for classification reasoning.
        use_fallbacks: When False and ``probe_url`` set, probe that URL only.

    Returns:
        Governance-enveloped observation payload with ``classification``, probes,
        ``prefer_ipv4_bit_set``, and attempt lists when multi-host was used.

    Side effects:
        Outbound curl probes and registry/binding reads on live Windows unless
        injectors supplied. No registry writes.

    Failure modes:
        Non-Windows without injectors → ``unsupported_platform``.
    """
    if platform.system() != "Windows" and ipv4_probe is None and ipv6_probe is None:
        if disabled_components is None and wifi_ipv6_enabled is None:
            return attach_governance_envelope(_unsupported())

    attempts_meta: dict[str, Any] = {}
    if ipv4_probe is not None and ipv6_probe is not None:
        v4, v6 = ipv4_probe, ipv6_probe
        urls = (
            list(probe_urls)
            if probe_urls
            else ([probe_url] if probe_url else list(DEFAULT_PROBE_URLS))
        )
    else:
        if probe_urls is not None:
            urls = list(probe_urls)
        elif probe_url and not use_fallbacks:
            urls = [probe_url]
        elif probe_url:
            urls = [probe_url, *[u for u in DEFAULT_PROBE_URLS if u != probe_url]]
        else:
            urls = list(DEFAULT_PROBE_URLS)
        multi = probe_dual_stack_multi(probe_urls=urls, timeout=timeout, run=run)
        v4 = multi["ipv4_probe"]
        v6 = multi["ipv6_probe"]
        attempts_meta = {
            "ipv4_attempts": multi["ipv4_attempts"],
            "ipv6_attempts": multi["ipv6_attempts"],
            "probe_urls": multi["probe_urls"],
        }

    dc = disabled_components if disabled_components is not None else read_disabled_components()
    prefer = bool(dc is not None and (int(dc) & PREFER_IPV4_BIT))
    wifi = (
        wifi_ipv6_enabled if wifi_ipv6_enabled is not None else wifi_ipv6_binding_enabled(run=run)
    )
    classification = classify_ipv6_path(
        ipv4_ok=bool(v4.get("ok")),
        ipv6_ok=bool(v6.get("ok")),
        prefer_ipv4_enabled=prefer,
        has_global_ipv6=has_global_ipv6,
    )
    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "probe_url": (v4.get("url") or probe_url or DEFAULT_PROBE_URL),
        "ipv4_probe": v4,
        "ipv6_probe": v6,
        "disabled_components": dc,
        "prefer_ipv4_bit_set": prefer,
        "wifi_ipv6_binding_enabled": wifi,
        "classification": classification["primary_classification"],
        "classification_result": classification,
        "limitations": classification["limitations"],
        **attempts_meta,
    }
    return attach_governance_envelope(payload)


def investigate_ipv6_path(
    *,
    probe_url: str | None = None,
    timeout: float = 8.0,
    run: Callable[..., Any] | None = None,
    network_context: dict[str, Any] | None = None,
    diagnosis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One-shot operator investigate: network context + multi-host path + next step.

    Args:
        probe_url: Optional primary HTTPS URL for diagnose fallbacks.
        timeout: Probe timeout seconds.
        run: Injectable subprocess runner.
        network_context: Injected Wi-Fi/DNS/proxy context (tests).
        diagnosis: Injected diagnose payload (tests); skips live probes when set.

    Returns:
        Governance-enveloped dict with ``network_context``, ``path``,
        ``process_elevated``, and structured ``operator_next_step``
        (``kind`` / ``command`` / ``reason``).

    Side effects:
        Read-only probes and registry/PowerShell reads only.

    Idempotency:
        Safe to re-run; does not mutate host state.
    """
    if platform.system() != "Windows" and diagnosis is None and network_context is None:
        return attach_governance_envelope(_unsupported())

    run_fn = run or subprocess.run
    ctx = network_context if network_context is not None else collect_network_context(run=run_fn)
    diag = diagnosis
    if diag is None:
        diag = diagnose_ipv6_path(
            probe_url=probe_url,
            timeout=timeout,
            run=run_fn,
            has_global_ipv6=ctx.get("has_global_ipv6"),
        )
        if diag.get("unsupported_platform"):
            return diag

    classification = str(diag.get("classification") or "")
    prefer = bool(diag.get("prefer_ipv4_bit_set"))
    proxy_enable = ctx.get("wininet_proxy_enable")
    elevated = is_process_elevated()
    next_step = _operator_next_step(
        classification=classification,
        prefer_ipv4_enabled=prefer,
        proxy_enable=int(proxy_enable) if proxy_enable is not None else None,
        elevated=elevated,
    )
    payload = {
        "timestamp_utc": _utc_now(),
        "command": "ipv6-path",
        "network_context": ctx,
        "path": {
            "classification": classification,
            "ipv4_ok": (diag.get("ipv4_probe") or {}).get("ok"),
            "ipv6_ok": (diag.get("ipv6_probe") or {}).get("ok"),
            "prefer_ipv4_bit_set": prefer,
            "disabled_components": diag.get("disabled_components"),
            "wifi_ipv6_binding_enabled": diag.get("wifi_ipv6_binding_enabled"),
            "ipv4_probe": diag.get("ipv4_probe"),
            "ipv6_probe": diag.get("ipv6_probe"),
            "ipv4_attempts": diag.get("ipv4_attempts"),
            "ipv6_attempts": diag.get("ipv6_attempts"),
            "classification_result": diag.get("classification_result"),
        },
        "process_elevated": elevated,
        "operator_next_step": next_step,
        "limitations": diag.get("limitations") or list(DEFAULT_SAFETY_NOTES),
    }
    return attach_governance_envelope(payload)


def _prefer_dry_run_next_step(
    *,
    already: bool,
    elevated: bool | None,
    diagnosis: dict[str, Any] | None,
) -> dict[str, Any]:
    """Structured guidance appended after prefer-IPv4 dry-run preview."""
    classification = None
    ipv6_ok = None
    if diagnosis:
        classification = diagnosis.get("classification")
        ipv6_ok = (diagnosis.get("ipv6_probe") or {}).get("ok")
    if already:
        return {
            "kind": "reboot",
            "command": None,
            "reason": (
                "Prefer-IPv4 bit already set. Reboot so Edge/Chrome/Firefox reload the stack; "
                "do not run ipv6-restore-preference until IPv6 probes succeed."
            ),
        }
    if classification == "IPV6_PATH_BLACKHOLE" or ipv6_ok is False:
        return {
            "kind": "prefer_ipv4_apply_elevated",
            "command": ELEVATED_APPLY_HINT,
            "reason": (
                "Blackhole pattern observed. Apply prefer-IPv4 elevated, then reboot. "
                "Do not restore IPv6 preference until ipv6-path shows IPv6 OK."
            ),
        }
    if elevated is False:
        return {
            "kind": "prefer_ipv4_apply_elevated",
            "command": ELEVATED_APPLY_HINT,
            "reason": "Preview only; live apply needs an elevated shell, then reboot.",
        }
    return {
        "kind": "prefer_ipv4_apply_elevated",
        "command": ELEVATED_APPLY_HINT,
        "reason": "Preview only. Live apply with token, then reboot.",
    }


def _restore_dry_run_next_step(
    *,
    bit_set: bool,
    elevated: bool | None,
    diagnosis: dict[str, Any] | None,
) -> dict[str, Any]:
    """Structured guidance appended after restore dry-run preview."""
    classification = None
    ipv6_ok = None
    if diagnosis:
        classification = diagnosis.get("classification")
        ipv6_ok = (diagnosis.get("ipv6_probe") or {}).get("ok")
    if not bit_set:
        return {
            "kind": "observe",
            "command": "python -m windows_network_toolkit ipv6-path",
            "reason": "Prefer-IPv4 bit already clear; nothing to restore. Re-check path with ipv6-path.",
        }
    if classification == "IPV6_PATH_BLACKHOLE" or ipv6_ok is False:
        return {
            "kind": "keep_prefer_ipv4",
            "command": None,
            "reason": (
                "IPv6 still failing. Do NOT live-apply restore — browsers may hang again. "
                "Keep prefer-IPv4, reboot if you just applied it, fix router/ISP first."
            ),
        }
    if ipv6_ok is True:
        cmd = ELEVATED_RESTORE_HINT
        if elevated is False:
            return {
                "kind": "restore_apply_elevated",
                "command": cmd,
                "reason": "IPv6 probes OK. Safe to clear prefer-IPv4 in an elevated shell, then reboot.",
            }
        return {
            "kind": "restore_apply_elevated",
            "command": cmd,
            "reason": "IPv6 probes OK. Live-apply restore with token, then reboot.",
        }
    return {
        "kind": "verify_before_restore",
        "command": "python -m windows_network_toolkit ipv6-path",
        "reason": (
            "Preview only. Run ipv6-path first; live-apply restore only when IPv6 is OK, "
            "otherwise Edge/Chrome/Firefox may blackhole again."
        ),
    }


def run_prefer_ipv4(
    *,
    dry_run: bool = True,
    confirm: str = "",
    also_flush_dns: bool = True,
    run: Callable[..., Any] | None = None,
    read_dc: Callable[[], int | None] | None = None,
    write_dc: Callable[[int], None] | None = None,
    diagnose_first: bool = True,
    require_elevation: bool = True,
    elevated: bool | None = None,
) -> dict[str, Any]:
    """Preview or apply prefer-IPv4 (``DisabledComponents |= 0x20``).

    Args:
        dry_run: When True (default), plan only — no registry write.
        confirm: Must equal ``PREFER_IPV4_OVER_IPV6`` for live apply.
        also_flush_dns: Flush DNS resolver cache after successful apply.
        run: Injectable subprocess runner (DNS flush / diagnose).
        read_dc / write_dc: Injectable registry accessors for tests.
        diagnose_first: Include a diagnose snapshot when on Windows.
        require_elevation: When True, refuse live apply if not elevated.
        elevated: Injected elevation flag for tests.

    Returns:
        Governance-enveloped dict with ``status``
        (``preview`` / ``blocked`` / ``needs_elevation`` / ``noop`` / ``applied`` /
        ``failed``), ``action_allowed``, planned DWORD values, and audit flag.

    Side effects:
        Live apply writes HKLM ``DisabledComponents``, may flush DNS, appends
        ``.audit/ipv6-prefer-ipv4.jsonl``. Requires Administrator for live write.

    Idempotency:
        Re-apply when bit already set → ``noop`` (no write). Preview is always safe.

    Audit Notes:
        What could go wrong: prefer-IPv4 on a host that needs working IPv6.
        Detection: audit JSONL + ``ipv6-path-status`` / registry DWORD.
        Recovery: ``ipv6-restore-preference`` then reboot.
    """
    if platform.system() != "Windows":
        if read_dc is None:
            return attach_governance_envelope(_unsupported())

    if is_demo_mode():
        dry_run = True

    reader = read_dc or read_disabled_components
    writer = write_dc or write_disabled_components
    run_fn = run or subprocess.run
    elev = elevated if elevated is not None else is_process_elevated()

    before = reader()
    before_i = int(before) if before is not None else 0
    after_planned = before_i | PREFER_IPV4_BIT
    already = bool(before_i & PREFER_IPV4_BIT)

    token_ok = (confirm or "") == CONFIRMATION_PHRASE
    action_allowed = (not dry_run) and token_ok and not is_demo_mode()

    diagnosis = (
        diagnose_ipv6_path(run=run_fn)
        if diagnose_first and platform.system() == "Windows"
        else None
    )

    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "action": "PREFER_IPV4_OVER_IPV6",
        "dry_run": dry_run,
        "action_allowed": action_allowed,
        "confirmation_required": CONFIRMATION_PHRASE,
        "confirmation_accepted": token_ok,
        "process_elevated": elev,
        "disabled_components_before": before,
        "disabled_components_planned": after_planned,
        "prefer_ipv4_already_set": already,
        "reboot_recommended": True,
        "adapter_disable_auto_apply": False,
        "adapter_disable_note": (
            "ADAPTER_DISABLE is blocked in safety.py; disable Wi-Fi IPv6 binding only "
            "manually if prefer-IPv4 is insufficient after reboot."
        ),
        "planned_change": {
            "registry": rf"HKLM\{TCPIP6_PARAMETERS}\DisabledComponents",
            "operation": f"OR with 0x{PREFER_IPV4_BIT:X} (prefer IPv4 over IPv6)",
            "from": before_i,
            "to": after_planned,
        },
        "elevated_apply_command": ELEVATED_APPLY_HINT,
        "limitations": list(DEFAULT_SAFETY_NOTES)
        + [
            "Prefer-IPv4 is a host mitigation, not an ISP IPv6 repair.",
            "Reboot required for Edge/OS to fully reload DisabledComponents.",
        ],
    }
    if diagnosis is not None:
        payload["diagnosis"] = {
            "classification": diagnosis.get("classification"),
            "ipv4_ok": (diagnosis.get("ipv4_probe") or {}).get("ok"),
            "ipv6_ok": (diagnosis.get("ipv6_probe") or {}).get("ok"),
        }

    if dry_run:
        payload["status"] = "preview"
        next_step = _prefer_dry_run_next_step(
            already=already, elevated=elev, diagnosis=diagnosis
        )
        payload["operator_next_step"] = next_step
        payload["message"] = (
            "Dry-run: no registry write. "
            f"Next: {next_step.get('reason')} "
            f"Command: {next_step.get('command') or '(reboot / none)'}."
        )
    elif not token_ok:
        payload["status"] = "blocked"
        payload["message"] = f"Live apply blocked: confirm must be exactly {CONFIRMATION_PHRASE}."
    elif require_elevation and elev is False and write_dc is None:
        payload["status"] = "needs_elevation"
        payload["action_allowed"] = False
        payload["message"] = (
            "Live apply needs an elevated (Administrator) shell. " f"Re-run: {ELEVATED_APPLY_HINT}"
        )
    elif already:
        payload["status"] = "noop"
        payload["message"] = (
            "Prefer-IPv4 bit already set; no registry change. Reboot if Edge still stalls."
        )
        payload["action_allowed"] = True
    else:
        try:
            writer(after_planned)
            payload["disabled_components_after"] = after_planned
            payload["status"] = "applied"
            payload["message"] = "Prefer-IPv4 bit applied. Reboot recommended."
            if also_flush_dns:
                try:
                    run_fn(
                        ["ipconfig", "/flushdns"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    payload["dns_flushed"] = True
                except (OSError, subprocess.SubprocessError) as exc:
                    payload["dns_flushed"] = False
                    payload["dns_flush_error"] = str(exc)[:200]
        except OSError as exc:
            winerr = getattr(exc, "winerror", None)
            if winerr == 5 or "Access is denied" in str(exc):
                payload["status"] = "needs_elevation"
                payload["action_allowed"] = False
                payload["message"] = (
                    "Registry write access denied. " f"Re-run elevated: {ELEVATED_APPLY_HINT}"
                )
            else:
                payload["status"] = "failed"
                payload["action_allowed"] = False
                payload["message"] = "Registry write failed: " + str(exc)[:240]

    audit_ok, _audit_err = append_audit_dict(
        {
            "event_type": "ipv6.prefer_ipv4",
            "command": "ipv6-prefer-ipv4",
            "dry_run": dry_run,
            "status": payload.get("status"),
            "action_allowed": payload.get("action_allowed"),
            "disabled_components_before": before,
            "disabled_components_planned": after_planned,
        },
        log_name="ipv6-prefer-ipv4.jsonl",
    )
    payload["audit_appended"] = audit_ok

    return attach_governance_envelope(payload)


def run_restore_ipv6_preference(
    *,
    dry_run: bool = True,
    confirm: str = "",
    also_flush_dns: bool = True,
    run: Callable[..., Any] | None = None,
    read_dc: Callable[[], int | None] | None = None,
    write_dc: Callable[[int], None] | None = None,
    require_elevation: bool = True,
    elevated: bool | None = None,
    diagnose_first: bool = True,
) -> dict[str, Any]:
    """Preview or clear prefer-IPv4 bit (``DisabledComponents &= ~0x20``).

    Decision intent:
        After ISP/router IPv6 is healthy again, restore normal IPv6 preference by
        clearing Microsoft prefer-IPv4 bit without touching other DisabledComponents bits.

    Args:
        dry_run: When True (default), plan only.
        confirm: Must equal ``RESTORE_IPV6_PREFERENCE`` for live apply.
        also_flush_dns: Flush DNS after successful apply.
        run / read_dc / write_dc: Injectables for tests.
        require_elevation / elevated: Elevation gate (same contract as prefer-IPv4).
        diagnose_first: When True on Windows, attach path diagnosis to dry-run guidance.

    Returns:
        Governance-enveloped dict with ``status``, planned DWORD, ``operator_next_step``
        on dry-run, and audit flag. Other DisabledComponents bits are preserved.

    Side effects:
        Live apply writes HKLM, may flush DNS, appends
        ``.audit/ipv6-restore-preference.jsonl``. Dry-run may run read-only probes.

    Idempotency:
        Bit already clear → ``noop``.

    Audit Notes:
        What could go wrong: restoring IPv6 preference while path still blackholed
        may bring Edge hangs back.
        Detection: re-run ``ipv6-path``; check ``prefer_ipv4_bit_set``.
        Recovery: re-apply prefer-IPv4 with ``PREFER_IPV4_OVER_IPV6`` then reboot.
    """
    if platform.system() != "Windows":
        if read_dc is None:
            return attach_governance_envelope(_unsupported())

    if is_demo_mode():
        dry_run = True

    reader = read_dc or read_disabled_components
    writer = write_dc or write_disabled_components
    run_fn = run or subprocess.run
    elev = elevated if elevated is not None else is_process_elevated()

    before = reader()
    before_i = int(before) if before is not None else 0
    after_planned = before_i & ~PREFER_IPV4_BIT
    bit_set = bool(before_i & PREFER_IPV4_BIT)

    token_ok = (confirm or "") == RESTORE_CONFIRMATION_PHRASE
    action_allowed = (not dry_run) and token_ok and not is_demo_mode()

    diagnosis = (
        diagnose_ipv6_path(run=run_fn)
        if diagnose_first and platform.system() == "Windows"
        else None
    )

    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "action": "RESTORE_IPV6_PREFERENCE",
        "dry_run": dry_run,
        "action_allowed": action_allowed,
        "confirmation_required": RESTORE_CONFIRMATION_PHRASE,
        "confirmation_accepted": token_ok,
        "process_elevated": elev,
        "disabled_components_before": before,
        "disabled_components_planned": after_planned,
        "prefer_ipv4_bit_was_set": bit_set,
        "reboot_recommended": True,
        "planned_change": {
            "registry": rf"HKLM\{TCPIP6_PARAMETERS}\DisabledComponents",
            "operation": f"AND NOT 0x{PREFER_IPV4_BIT:X} (restore IPv6 preference)",
            "from": before_i,
            "to": after_planned,
        },
        "elevated_apply_command": ELEVATED_RESTORE_HINT,
        "limitations": list(DEFAULT_SAFETY_NOTES)
        + [
            "Clearing prefer-IPv4 returns default Happy Eyeballs behavior; broken IPv6 may hang Edge again.",
            "Reboot recommended after DisabledComponents change.",
            "Only the 0x20 bit is cleared; other DisabledComponents bits are preserved.",
        ],
    }
    if diagnosis is not None:
        payload["diagnosis"] = {
            "classification": diagnosis.get("classification"),
            "ipv4_ok": (diagnosis.get("ipv4_probe") or {}).get("ok"),
            "ipv6_ok": (diagnosis.get("ipv6_probe") or {}).get("ok"),
        }

    if dry_run:
        payload["status"] = "preview"
        next_step = _restore_dry_run_next_step(
            bit_set=bit_set, elevated=elev, diagnosis=diagnosis
        )
        payload["operator_next_step"] = next_step
        payload["message"] = (
            "Dry-run: no registry write. "
            f"Next: {next_step.get('reason')} "
            f"Command: {next_step.get('command') or '(none — keep prefer-IPv4 / reboot)'}."
        )
    elif not token_ok:
        payload["status"] = "blocked"
        payload["message"] = (
            f"Live apply blocked: confirm must be exactly {RESTORE_CONFIRMATION_PHRASE}."
        )
    elif require_elevation and elev is False and write_dc is None:
        payload["status"] = "needs_elevation"
        payload["action_allowed"] = False
        payload["message"] = (
            "Live apply needs an elevated (Administrator) shell. "
            f"Re-run: {ELEVATED_RESTORE_HINT}"
        )
    elif not bit_set:
        payload["status"] = "noop"
        payload["message"] = (
            "Prefer-IPv4 bit already clear; IPv6 preference not overridden by 0x20."
        )
        payload["action_allowed"] = True
    else:
        try:
            writer(after_planned)
            payload["disabled_components_after"] = after_planned
            payload["status"] = "applied"
            payload["message"] = (
                "Prefer-IPv4 bit cleared. Reboot recommended to restore IPv6 preference."
            )
            if also_flush_dns:
                try:
                    run_fn(
                        ["ipconfig", "/flushdns"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    payload["dns_flushed"] = True
                except (OSError, subprocess.SubprocessError) as exc:
                    payload["dns_flushed"] = False
                    payload["dns_flush_error"] = str(exc)[:200]
        except OSError as exc:
            winerr = getattr(exc, "winerror", None)
            if winerr == 5 or "Access is denied" in str(exc):
                payload["status"] = "needs_elevation"
                payload["action_allowed"] = False
                payload["message"] = (
                    "Registry write access denied. " f"Re-run elevated: {ELEVATED_RESTORE_HINT}"
                )
            else:
                payload["status"] = "failed"
                payload["action_allowed"] = False
                payload["message"] = "Registry write failed: " + str(exc)[:240]

    audit_ok, _audit_err = append_audit_dict(
        {
            "event_type": "ipv6.restore_preference",
            "command": "ipv6-restore-preference",
            "dry_run": dry_run,
            "status": payload.get("status"),
            "action_allowed": payload.get("action_allowed"),
            "disabled_components_before": before,
            "disabled_components_planned": after_planned,
        },
        log_name="ipv6-restore-preference.jsonl",
    )
    payload["audit_appended"] = audit_ok

    return attach_governance_envelope(payload)
