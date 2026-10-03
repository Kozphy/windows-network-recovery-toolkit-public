"""DNS / Edge ERR_NAME_NOT_RESOLVED diagnose and gated remediation.

Module responsibility:
    Detect Windows DNS / Edge Secure-DNS patterns correlated with browser
    ``ERR_NAME_NOT_RESOLVED`` (and related DNS probe failures) while Cursor or
    other non-browser clients may still work. Preview or apply: prefer public
    DNS (1.1.1.1 / 8.8.8.8 before router), flush resolver cache, and force Edge
    to use the OS DNS client (DoH off + built-in async DNS disabled).

System placement:
    CLI: ``dns-edge-status`` (read-only), ``dns-edge-fix`` (preview/apply).
    Safety token: ``FIX_ERR_NAME_NOT_RESOLVED`` in ``windows_network_toolkit.safety``.
    Complements ``ipv6-path`` (dual-stack hangs) and ``proxy-status`` (WinINET).

Key invariants:
    * Dry-run default; live apply needs exact confirmation token.
    * Does not reset firewall, disable adapters, or kill proxy processes.
    * Optional Edge process restart requires ``--restart-edge`` on live apply.
    * Observation only for diagnose — not proof of ISP DNS malice.

Side effects:
    Diagnose: DNS lookups, registry/policy reads, adapter DNS reads. With
    ``--url``: direct UDP/53 queries to root, TLD, and the domain's own
    nameservers plus 1.1.1.1 / 8.8.8.8 (read-only, no state change).
    Apply: may set Wi-Fi DNS servers (elevation), flush DNS, write HKCU Edge
    policy values, optionally stop ``msedge`` processes.

Failure modes:
    Non-Windows → unsupported. Missing elevation → ``needs_elevation`` for DNS set.
    Wrong/missing confirm → blocked.

Audit Notes:
    What could go wrong: wrong DNS on corporate NRPT hosts; Edge policy may be
    overridden by MDM. Detection: audit JSONL + re-run ``dns-edge-status``.
    Recovery: restore DHCP DNS (``Set-DnsClientServerAddress -ResetServerAddresses``)
    and remove Edge policy values; reopen Edge.
"""

from __future__ import annotations

import platform
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from src.proxy_drift.dns_health import assess_dns_mismatch
from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.dns_authoritative import check_authoritative_dns
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, DEFAULT_SAFETY_NOTES, is_demo_mode

CONFIRMATION_PHRASE = CONFIRMATION_TOKENS.get(
    "FIX_ERR_NAME_NOT_RESOLVED", "FIX_ERR_NAME_NOT_RESOLVED"
)
DEFAULT_PROBE_HOSTS: tuple[str, ...] = (
    "www.google.com",
    "www.cloudflare.com",
    "www.microsoft.com",
)
PREFERRED_DNS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
ELEVATED_APPLY_HINT = (
    "python -m windows_network_toolkit dns-edge-fix "
    "--dry-run false --confirm FIX_ERR_NAME_NOT_RESOLVED"
)
EDGE_POLICY_KEY = r"Software\Policies\Microsoft\Edge"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unsupported() -> dict[str, Any]:
    return {
        "unsupported_platform": True,
        "platform": platform.system(),
        "message": "dns-edge commands require Windows.",
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


def read_wifi_dns(
    *,
    interface_alias: str = "Wi-Fi",
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Read Wi-Fi IPv4 address, gateway, and DNS server list (read-only)."""
    if platform.system() != "Windows":
        return {
            "interface_alias": interface_alias,
            "ipv4": None,
            "gateway": None,
            "dns_servers": [],
            "error": "requires_windows",
        }
    run_fn = run or subprocess.run
    ps = (
        f"$c=Get-NetIPConfiguration -InterfaceAlias '{interface_alias}' "
        "-ErrorAction SilentlyContinue; "
        "if(-not $c){'MISSING'; exit}; "
        "$ip=($c.IPv4Address | Select-Object -First 1).IPAddress; "
        "$gw=($c.IPv4DefaultGateway | Select-Object -First 1).NextHop; "
        "$dns=((Get-DnsClientServerAddress -InterfaceAlias "
        f"'{interface_alias}' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue).ServerAddresses) -join ','; "
        "Write-Output $ip; Write-Output '---'; Write-Output $gw; "
        "Write-Output '---'; Write-Output $dns"
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
        if (completed.stdout or "").strip().startswith("MISSING") or len(parts) < 3:
            return {
                "interface_alias": interface_alias,
                "ipv4": None,
                "gateway": None,
                "dns_servers": [],
                "error": "interface_not_found",
            }
        ipv4 = parts[0].strip() or None
        gateway = parts[1].strip() or None
        dns_raw = parts[2].strip()
        servers = [s.strip() for s in dns_raw.split(",") if s.strip()]
        return {
            "interface_alias": interface_alias,
            "ipv4": ipv4,
            "gateway": gateway,
            "dns_servers": servers,
            "error": None,
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "interface_alias": interface_alias,
            "ipv4": None,
            "gateway": None,
            "dns_servers": [],
            "error": str(exc)[:200],
        }


def resolve_host(
    host: str,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Resolve a hostname via PowerShell ``Resolve-DnsName`` (A/AAAA)."""
    run_fn = run or subprocess.run
    if platform.system() != "Windows":
        return {"host": host, "ok": False, "addresses": [], "error": "requires_windows"}
    ps = (
        f"try {{ $r=Resolve-DnsName -Name '{host}' -ErrorAction Stop; "
        "($r | ForEach-Object { if($_.IPAddress){$_.IPAddress} }) -join ',' } "
        "catch { 'ERR:' + $_.Exception.Message }"
    )
    try:
        completed = run_fn(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
        text = (completed.stdout or "").strip()
        if text.startswith("ERR:") or not text:
            return {
                "host": host,
                "ok": False,
                "addresses": [],
                "error": text[:240] or f"exit={completed.returncode}",
            }
        addrs = [a.strip() for a in text.split(",") if a.strip()]
        return {"host": host, "ok": bool(addrs), "addresses": addrs[:12], "error": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"host": host, "ok": False, "addresses": [], "error": str(exc)[:200]}


def read_edge_dns_policy() -> dict[str, Any]:
    """Read HKCU Edge policy values for DoH / built-in DNS client."""
    if platform.system() != "Windows":
        return {"dns_over_https_mode": None, "builtin_dns_client_enabled": None}
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, EDGE_POLICY_KEY, 0, winreg.KEY_READ) as key:
            try:
                doh, _ = winreg.QueryValueEx(key, "DnsOverHttpsMode")
            except OSError:
                doh = None
            try:
                builtin, _ = winreg.QueryValueEx(key, "BuiltInDnsClientEnabled")
            except OSError:
                builtin = None
            return {
                "dns_over_https_mode": doh,
                "builtin_dns_client_enabled": builtin,
            }
    except OSError:
        return {"dns_over_https_mode": None, "builtin_dns_client_enabled": None}


def write_edge_dns_policy(*, doh_mode: str = "off", builtin_enabled: int = 0) -> None:
    """Write HKCU Edge policy forcing OS DNS (DoH off, built-in client disabled)."""
    import winreg

    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, EDGE_POLICY_KEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, "DnsOverHttpsMode", 0, winreg.REG_SZ, doh_mode)
        winreg.SetValueEx(key, "BuiltInDnsClientEnabled", 0, winreg.REG_DWORD, int(builtin_enabled))


def set_wifi_dns_servers(
    servers: list[str],
    *,
    interface_alias: str = "Wi-Fi",
    run: Callable[..., Any] | None = None,
) -> None:
    """Set Wi-Fi IPv4 DNS server list (requires elevation)."""
    run_fn = run or subprocess.run
    joined = ",".join(f"'{s}'" for s in servers)
    ps = (
        f"Set-DnsClientServerAddress -InterfaceAlias '{interface_alias}' "
        f"-ServerAddresses @({joined})"
    )
    completed = run_fn(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "dns_set_failed").strip()
        raise OSError(err[:240])


def flush_dns_cache(*, run: Callable[..., Any] | None = None) -> bool:
    """Flush Windows DNS resolver cache via ``ipconfig /flushdns``."""
    run_fn = run or subprocess.run
    try:
        completed = run_fn(
            ["ipconfig", "/flushdns"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def stop_edge_processes(*, run: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Force-stop Microsoft Edge processes so DNS/policy reloads.

    Side effects:
        Stops ``msedge`` processes. Does not start Edge again.
    """
    run_fn = run or subprocess.run
    try:
        completed = run_fn(
            ["taskkill", "/IM", "msedge.exe", "/F"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        # taskkill exits 128 when no matching process; still treat as success for reload intent
        return {
            "restarted": True,
            "method": "taskkill",
            "returncode": getattr(completed, "returncode", None),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"restarted": False, "method": "taskkill", "error": str(exc)[:200]}


def classify_dns_edge(
    *,
    resolve_ok_count: int,
    resolve_total: int,
    wifi: dict[str, Any],
    edge_policy: dict[str, Any],
    mismatch: dict[str, Any],
) -> dict[str, Any]:
    """Classify ERR_NAME_NOT_RESOLVED-related DNS/Edge posture.

    Decision intent:
        Separate OS DNS failure from Edge-only Secure/async DNS issues and
        router-first DNS ordering that correlates with browser name errors.
    """
    limitations = [
        "System Resolve-DnsName OK does not prove Edge's resolver path is healthy.",
        "Corporate NRPT / MDM may override adapter DNS and Edge policy.",
        *DEFAULT_SAFETY_NOTES,
    ]
    servers = list(wifi.get("dns_servers") or [])
    primary = servers[0] if servers else None
    public_first = bool(primary in PREFERRED_DNS)
    doh = str(edge_policy.get("dns_over_https_mode") or "").lower()
    builtin = edge_policy.get("builtin_dns_client_enabled")
    edge_forced_os = doh == "off" and builtin in (0, "0", False)

    if resolve_total > 0 and resolve_ok_count == 0:
        return {
            "primary_classification": "DNS_RESOLVE_FAILED",
            "severity": "high",
            "confidence": 0.85,
            "reasoning": "No probe host resolved via OS DNS — browser ERR_NAME_NOT_RESOLVED expected.",
            "recommended_next_actions": [
                "Run: python -m windows_network_toolkit dns-edge-fix --dry-run true",
                f"Apply elevated: {ELEVATED_APPLY_HINT}",
                "Check Wi-Fi / router WAN if public DNS also fails.",
            ],
            "limitations": limitations,
        }

    if resolve_ok_count > 0 and (
        not edge_forced_os or not public_first or mismatch.get("primary_off_subnet")
    ):
        reasons = []
        if not public_first:
            reasons.append("primary DNS is not 1.1.1.1/8.8.8.8 (router-first is common)")
        if not edge_forced_os:
            reasons.append("Edge DoH/built-in DNS not forced to OS resolver")
        if mismatch.get("primary_off_subnet"):
            reasons.append(str(mismatch.get("rationale") or "primary DNS off-subnet"))
        return {
            "primary_classification": "ERR_NAME_NOT_RESOLVED_LIKELY",
            "severity": "medium",
            "confidence": 0.8,
            "reasoning": (
                "OS DNS can resolve probes, but Edge/DNS posture still matches "
                "browser ERR_NAME_NOT_RESOLVED risk: " + "; ".join(reasons)
            ),
            "recommended_next_actions": [
                "Run: python -m windows_network_toolkit dns-edge-fix --dry-run true",
                f"Apply: {ELEVATED_APPLY_HINT} [--restart-edge]",
                "If still failing: edge://net-internals/#dns → Clear host cache.",
            ],
            "limitations": limitations,
        }

    return {
        "primary_classification": "DNS_EDGE_OK",
        "severity": "info",
        "confidence": 0.75,
        "reasoning": "OS DNS resolves probes; public DNS preferred; Edge policy forces OS DNS.",
        "recommended_next_actions": [
            "If Edge still shows ERR_NAME_NOT_RESOLVED, clear Edge host cache or try InPrivate.",
            "Also run ipv6-path if pages hang rather than fail DNS.",
        ],
        "limitations": limitations,
    }


def _target_next_step(authoritative: dict[str, Any]) -> dict[str, Any] | None:
    """Override the next step when the target site's own DNS decides the outcome."""
    verdict = authoritative.get("verdict")
    if verdict in ("site_side", "site_side_intermittent"):
        return {
            "kind": "site_side_dns",
            "command": None,
            "reason": (
                f"{authoritative.get('summary')} Changing this PC's DNS or Edge settings "
                "will not fix it; FIX_ERR_NAME_NOT_RESOLVED is not recommended."
            ),
        }
    if verdict == "client_side":
        return {
            "kind": "dns_edge_fix_apply",
            "command": ELEVATED_APPLY_HINT + " --restart-edge",
            "reason": str(authoritative.get("summary")),
        }
    return None


def diagnose_dns_edge(
    *,
    interface_alias: str = "Wi-Fi",
    probe_hosts: tuple[str, ...] | list[str] = DEFAULT_PROBE_HOSTS,
    run: Callable[..., Any] | None = None,
    wifi: dict[str, Any] | None = None,
    edge_policy: dict[str, Any] | None = None,
    resolves: list[dict[str, Any]] | None = None,
    url: str | None = None,
    authoritative: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read-only DNS + Edge policy diagnosis for ERR_NAME_NOT_RESOLVED.

    When ``url`` is given, also asks the target domain's own nameservers
    directly (``dns_authoritative``) so a broken site-side delegation is not
    mistaken for a local DNS problem.
    """
    if platform.system() != "Windows" and wifi is None and resolves is None:
        return attach_governance_envelope(_unsupported())

    wifi_snap = (
        wifi if wifi is not None else read_wifi_dns(interface_alias=interface_alias, run=run)
    )
    policy = edge_policy if edge_policy is not None else read_edge_dns_policy()
    resolve_rows = resolves
    if resolve_rows is None:
        resolve_rows = [resolve_host(h, run=run) for h in probe_hosts]

    ok_count = sum(1 for r in resolve_rows if r.get("ok"))
    mismatch = assess_dns_mismatch(
        interface_ipv4=wifi_snap.get("ipv4"),
        gateway=wifi_snap.get("gateway"),
        dns_servers=list(wifi_snap.get("dns_servers") or []),
    )
    classification = classify_dns_edge(
        resolve_ok_count=ok_count,
        resolve_total=len(resolve_rows),
        wifi=wifi_snap,
        edge_policy=policy,
        mismatch=mismatch,
    )
    planned_dns = list(PREFERRED_DNS)
    gw = wifi_snap.get("gateway")
    if gw and gw not in planned_dns:
        planned_dns.append(str(gw))

    next_step = {
        "kind": "dns_edge_fix_preview",
        "command": "python -m windows_network_toolkit dns-edge-fix --dry-run true",
        "reason": classification["reasoning"],
    }
    if classification["primary_classification"] == "DNS_EDGE_OK":
        next_step = {
            "kind": "observe",
            "command": None,
            "reason": "No DNS adapter change indicated from current probes/policy.",
        }
    elif classification["primary_classification"] != "DNS_EDGE_OK":
        next_step = {
            "kind": "dns_edge_fix_apply",
            "command": ELEVATED_APPLY_HINT + " --restart-edge",
            "reason": classification["reasoning"],
        }

    limitations = list(classification["limitations"])
    target: dict[str, Any] | None = None
    if url or authoritative is not None:
        target = authoritative if authoritative is not None else check_authoritative_dns(url or "")
        override = _target_next_step(target)
        if override is not None:
            next_step = override
        limitations.extend(
            item for item in target.get("limitations", []) if item not in limitations
        )

    payload = {
        "timestamp_utc": _utc_now(),
        "command": "dns-edge-status",
        "wifi": wifi_snap,
        "edge_policy": policy,
        "resolves": resolve_rows,
        "mismatch": mismatch,
        "planned_dns_servers": planned_dns,
        "classification": classification["primary_classification"],
        "classification_result": classification,
        "operator_next_step": next_step,
        "limitations": limitations,
    }
    if target is not None:
        payload["target_url"] = url
        payload["target_verdict"] = target.get("verdict")
        payload["authoritative_check"] = target
    return attach_governance_envelope(payload)


def run_dns_edge_fix(
    *,
    dry_run: bool = True,
    confirm: str = "",
    interface_alias: str = "Wi-Fi",
    restart_edge: bool = False,
    run: Callable[..., Any] | None = None,
    diagnose_first: bool = True,
    read_wifi: Callable[..., dict[str, Any]] | None = None,
    write_dns: Callable[[list[str]], None] | None = None,
    write_edge: Callable[..., None] | None = None,
    flush: Callable[[], bool] | None = None,
    restart: Callable[[], dict[str, Any]] | None = None,
    elevated: bool | None = None,
    require_elevation: bool = True,
) -> dict[str, Any]:
    """Preview or apply DNS + Edge OS-resolver remediation for ERR_NAME_NOT_RESOLVED."""
    if platform.system() != "Windows":
        if read_wifi is None and write_dns is None:
            return attach_governance_envelope(_unsupported())

    if is_demo_mode():
        dry_run = True

    run_fn = run or subprocess.run
    elev = elevated if elevated is not None else is_process_elevated()
    token_ok = (confirm or "") == CONFIRMATION_PHRASE
    action_allowed = (not dry_run) and token_ok and not is_demo_mode()

    wifi_fn = read_wifi or (lambda: read_wifi_dns(interface_alias=interface_alias, run=run_fn))
    before = wifi_fn()
    planned = list(PREFERRED_DNS)
    gw = before.get("gateway")
    if gw and gw not in planned:
        planned.append(str(gw))

    diagnosis = None
    if diagnose_first and platform.system() == "Windows":
        diagnosis = diagnose_dns_edge(interface_alias=interface_alias, run=run_fn, wifi=before)

    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "action": "FIX_ERR_NAME_NOT_RESOLVED",
        "dry_run": dry_run,
        "action_allowed": action_allowed,
        "confirmation_required": CONFIRMATION_PHRASE,
        "confirmation_accepted": token_ok,
        "process_elevated": elev,
        "restart_edge_requested": restart_edge,
        "dns_servers_before": before.get("dns_servers"),
        "dns_servers_planned": planned,
        "edge_policy_planned": {
            "DnsOverHttpsMode": "off",
            "BuiltInDnsClientEnabled": 0,
        },
        "elevated_apply_command": ELEVATED_APPLY_HINT + (" --restart-edge" if restart_edge else ""),
        "reboot_recommended": False,
        "limitations": list(DEFAULT_SAFETY_NOTES)
        + [
            "Does not modify corporate NRPT / MDM DNS policies.",
            "Optional Edge restart closes all Edge windows.",
        ],
    }
    if diagnosis is not None:
        payload["diagnosis"] = {
            "classification": diagnosis.get("classification"),
            "operator_next_step": diagnosis.get("operator_next_step"),
        }

    if dry_run:
        payload["status"] = "preview"
        next_step = {
            "kind": "dns_edge_fix_apply",
            "command": ELEVATED_APPLY_HINT + " --restart-edge",
            "reason": (
                "Preview only. Live apply sets public DNS first, forces Edge OS DNS, "
                "flushes cache; add --restart-edge to reload Edge."
            ),
        }
        if diagnosis and diagnosis.get("classification") == "DNS_EDGE_OK":
            next_step = {
                "kind": "observe",
                "command": None,
                "reason": "Diagnosis already DNS_EDGE_OK — apply only if Edge still fails.",
            }
        payload["operator_next_step"] = next_step
        payload["message"] = (
            f"Dry-run: no DNS/Edge changes. Next: {next_step['reason']} "
            f"Command: {next_step.get('command') or '(none)'}."
        )
    elif not token_ok:
        payload["status"] = "blocked"
        payload["message"] = f"Live apply blocked: confirm must be exactly {CONFIRMATION_PHRASE}."
    elif require_elevation and elev is False and write_dns is None:
        payload["status"] = "needs_elevation"
        payload["action_allowed"] = False
        payload["message"] = (
            f"Live DNS change needs an elevated shell. Re-run: {payload['elevated_apply_command']}"
        )
        payload["operator_next_step"] = {
            "kind": "dns_edge_fix_apply_elevated",
            "command": payload["elevated_apply_command"],
            "reason": payload["message"],
        }
    else:
        errors: list[str] = []
        try:
            dns_writer = write_dns or (
                lambda servers: set_wifi_dns_servers(
                    servers, interface_alias=interface_alias, run=run_fn
                )
            )
            dns_writer(planned)
            payload["dns_servers_after"] = planned
            payload["dns_updated"] = True
        except OSError as exc:
            payload["dns_updated"] = False
            errors.append(f"dns:{exc}"[:200])

        try:
            edge_writer = write_edge or write_edge_dns_policy
            edge_writer(doh_mode="off", builtin_enabled=0)
            payload["edge_policy_updated"] = True
        except OSError as exc:
            payload["edge_policy_updated"] = False
            errors.append(f"edge_policy:{exc}"[:200])

        flush_fn = flush or (lambda: flush_dns_cache(run=run_fn))
        payload["dns_flushed"] = bool(flush_fn())

        if restart_edge:
            restart_fn = restart or (lambda: stop_edge_processes(run=run_fn))
            payload["edge_restart"] = restart_fn()
        else:
            payload["edge_restart"] = {
                "restarted": False,
                "note": "Pass --restart-edge on live apply to stop msedge.exe",
            }

        if errors and not payload.get("dns_updated") and not payload.get("edge_policy_updated"):
            payload["status"] = "failed"
            payload["action_allowed"] = False
            payload["message"] = "Apply failed: " + "; ".join(errors)
        elif errors:
            payload["status"] = "partial"
            payload["message"] = (
                "Partial apply. " + "; ".join(errors) + " Reopen Edge and retry the site."
            )
            payload["errors"] = errors
        else:
            payload["status"] = "applied"
            payload["message"] = (
                "DNS preference + Edge OS-DNS policy applied; cache flushed. "
                "Reopen Edge (or re-run with --restart-edge) and retry the site."
            )
        payload["operator_next_step"] = {
            "kind": "reopen_edge_verify",
            "command": "python -m windows_network_toolkit dns-edge-status",
            "reason": "Reopen Edge and re-run dns-edge-status to verify classification.",
        }

    audit_ok, _audit_err = append_audit_dict(
        {
            "event_type": "dns.edge_fix",
            "command": "dns-edge-fix",
            "dry_run": dry_run,
            "status": payload.get("status"),
            "action_allowed": payload.get("action_allowed"),
            "dns_servers_planned": planned,
            "restart_edge": restart_edge,
        },
        log_name="dns-edge-fix.jsonl",
    )
    payload["audit_appended"] = audit_ok
    return attach_governance_envelope(payload)
