"""Ensure proxy health on repo/session start — dead-proxy auto-fix + guardian install.

Default behavior (safe):
  - Clear **dead** localhost WinINET proxies only.
  - Detect **active-but-broken** (listener up, proxy path fail, direct HTTPS ok)
    and clear with ``PREFER_DIRECT_WININET`` when confirm is supplied.
  - Install startup observability (guardian + boot trace) if missing.
  - Leave healthy active localhost / corporate proxies alone unless prefer_direct.

Optional ``prefer_direct`` (requires ``PREFER_DIRECT_WININET``):
  - Also clear an *active* (healthy) localhost WinINET proxy so browsers/apps
    always use direct access. Use when a flaky local Node proxy causes
    ``ERR_PROXY_CONNECTION_FAILED``.
"""

from __future__ import annotations

import platform
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.proxy_drift.auto_fix import read_proxy_drift_status, run_auto_fix_proxy
from src.proxy_drift.dns_health import collect_wifi_dns_snapshot
from src.proxy_drift.guardian_task import TASK_NAME as GUARDIAN_TASK
from src.proxy_drift.proxy_fix import apply_proxy_fix
from src.proxy_drift.startup_hook import startup_hook_path
from src.proxy_drift.startup_observability import (
    CONFIRM_INSTALL,
    install_startup_observability,
)
from src.proxy_guard.remediation import CONFIRMATION_PHRASE

CONFIRM_PREFER_DIRECT = "PREFER_DIRECT_WININET"
_SCHEMA = "ensure_proxy_health.v1"
_BOOT_TRACE_HOOK = "WNRT-ProxyBootTrace"
_GUARDIAN_HOOK = "WNRT-DeadProxyGuardian"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def observability_install_status(*, run: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Return whether guardian / boot-trace artifacts are present (task or Startup hook)."""
    subprocess_run = run if run is not None else subprocess.run
    guardian_hook = startup_hook_path(_GUARDIAN_HOOK).is_file()
    boot_hook = startup_hook_path(_BOOT_TRACE_HOOK).is_file()
    guardian_task = False
    boot_task = False
    try:
        g = subprocess_run(
            ["schtasks", "/Query", "/TN", GUARDIAN_TASK],
            capture_output=True,
            text=True,
            timeout=15,
        )
        guardian_task = g.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        guardian_task = False
    try:
        b = subprocess_run(
            ["schtasks", "/Query", "/TN", "WNRT-ProxyBootTrace"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        boot_task = b.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        boot_task = False
    guardian_ok = guardian_hook or guardian_task
    boot_ok = boot_hook or boot_task
    return {
        "guardian_present": guardian_ok,
        "boot_trace_present": boot_ok,
        "guardian_via": "task" if guardian_task else ("startup_hook" if guardian_hook else None),
        "boot_trace_via": "task" if boot_task else ("startup_hook" if boot_hook else None),
        "fully_installed": guardian_ok and boot_ok,
    }


def run_ensure_proxy_health(
    *,
    dry_run: bool = False,
    prefer_direct: bool = False,
    confirm: str = "",
    skip_observability_install: bool = False,
    skip_cursor_fix: bool = False,
    guardian_interval_seconds: int = 15,
    repo_root: Path | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run session ensure: dead-proxy fix, optional prefer-direct, install observability."""
    if platform.system() != "Windows":
        return {
            "schema_version": _SCHEMA,
            "unsupported_platform": True,
            "platform": platform.system(),
            "outcome": "unsupported",
        }

    subprocess_run = run if run is not None else subprocess.run
    repo = (repo_root or Path.cwd()).resolve()
    steps: list[dict[str, Any]] = []

    before = read_proxy_drift_status(run=subprocess_run)
    steps.append({"step": "status_before", "result": before})
    obs_before = observability_install_status(run=subprocess_run)
    steps.append({"step": "observability_status_before", "result": obs_before})

    auto = run_auto_fix_proxy(
        dry_run=dry_run,
        skip_guardian_install=True,
        skip_cursor_fix=skip_cursor_fix or dry_run,
        guardian_interval_seconds=guardian_interval_seconds,
        prefer_direct=prefer_direct,
        confirm=confirm,
        repo_root=repo,
        run=subprocess_run,
    )
    steps.append({"step": "auto_fix_proxy", "result": auto})

    prefer_result: dict[str, Any] | None = None
    after_auto = read_proxy_drift_status(run=subprocess_run)
    localhost_enabled = (
        int(after_auto.get("proxy_enable") or 0) == 1
        and after_auto.get("localhost_port") is not None
    )
    broken = bool(after_auto.get("is_broken_localhost_proxy"))
    # Broken path uses prefer-direct confirm even without --prefer-direct.
    should_prefer_clear = localhost_enabled and (prefer_direct or broken)
    if should_prefer_clear:
        if dry_run:
            prefer_result = {
                "action_taken": "preview_only",
                "reason": (
                    f"Would clear active-but-broken localhost WinINET proxy "
                    f"(confirm {CONFIRM_PREFER_DIRECT})."
                    if broken
                    else f"Would clear localhost WinINET proxy (confirm {CONFIRM_PREFER_DIRECT})."
                ),
                "proxy_server": after_auto.get("proxy_server"),
                "classification": after_auto.get("classification"),
            }
        elif confirm != CONFIRM_PREFER_DIRECT:
            prefer_result = {
                "action_taken": "blocked",
                "reason": f"Confirmation required: {CONFIRM_PREFER_DIRECT}",
                "proxy_server": after_auto.get("proxy_server"),
                "classification": after_auto.get("classification"),
            }
        else:
            prefer_result = apply_proxy_fix(
                dry_run=False,
                confirm=CONFIRMATION_PHRASE,
                clear_pac=False,
                run=subprocess_run,
            )
            prefer_result["prefer_direct"] = True
            prefer_result["cleared_broken_localhost"] = broken
        steps.append({"step": "prefer_direct", "result": prefer_result})

    obs_install: dict[str, Any] | None = None
    if not skip_observability_install:
        obs_now = observability_install_status(run=subprocess_run)
        if obs_now.get("fully_installed"):
            obs_install = {
                "action_taken": "already_installed",
                "status": obs_now,
                "reason": "Guardian and boot trace already present.",
            }
        elif dry_run:
            obs_install = {
                "action_taken": "preview_only",
                "confirmation_required": CONFIRM_INSTALL,
                "reason": "Would install startup observability (guardian + boot trace).",
                "status": obs_now,
            }
        else:
            obs_install = install_startup_observability(
                guardian_interval=guardian_interval_seconds,
                confirm=CONFIRM_INSTALL,
                dry_run=False,
            )
        steps.append({"step": "startup_observability", "result": obs_install})

    final = read_proxy_drift_status(run=subprocess_run)
    steps.append({"step": "status_final", "result": final})
    obs_final = observability_install_status(run=subprocess_run)
    steps.append({"step": "observability_status_final", "result": obs_final})

    final_broken = bool(final.get("is_broken_localhost_proxy"))
    prefer_blocked = bool(prefer_result and prefer_result.get("action_taken") == "blocked")
    if final.get("is_dead_localhost_proxy"):
        outcome = "still_dead" if not dry_run else "would_remediate"
    elif final_broken and prefer_blocked:
        outcome = "needs_prefer_direct_confirm"
    elif final_broken:
        outcome = "would_remediate" if dry_run else "localhost_proxy_broken"
    elif prefer_direct and localhost_enabled and prefer_blocked:
        outcome = "needs_prefer_direct_confirm"
    elif int(final.get("proxy_enable") or 0) == 1 and final.get("localhost_port") is not None:
        outcome = "localhost_proxy_active"
    else:
        outcome = "healthy"

    dns = collect_wifi_dns_snapshot(run=subprocess_run)
    steps.append({"step": "dns_health", "result": dns})
    if dns.get("primary_off_subnet") and outcome == "healthy":
        # Keep outcome healthy for proxy path; surface DNS as adjacent browser risk.
        pass

    result = {
        "schema_version": _SCHEMA,
        "timestamp_utc": _now(),
        "dry_run": dry_run,
        "prefer_direct": prefer_direct,
        "outcome": outcome,
        "classification": final.get("classification"),
        "legacy_classification": final.get("legacy_classification"),
        "is_broken_localhost_proxy": final_broken,
        "proxy_probe_ok": final.get("proxy_probe_ok"),
        "direct_probe_ok": final.get("direct_probe_ok"),
        "proxy_enable": final.get("proxy_enable"),
        "proxy_server": final.get("proxy_server"),
        "dns_health": dns,
        "observability_installed": bool(obs_final.get("fully_installed")),
        "steps": steps,
        "recommended_next_step": _recommend(outcome, prefer_direct, dns),
        "limitations": [
            "Default ensure clears dead localhost WinINET only — not corporate proxies.",
            "Active-but-broken (listener up, proxy path fail, direct ok) clears with PREFER_DIRECT_WININET.",
            "prefer_direct clears healthy active localhost proxies; may break intentional local tunnels.",
            "Observation ≠ registry writer proof; LinkedIn uses WinINET system proxy.",
            "dns_health is adapter heuristic only — not DNS malware attribution.",
        ],
    }
    try:
        from src.platform_core.audit.custody import append_custody_event

        event = "prefer_direct_applied" if prefer_direct and outcome == "healthy" and not dry_run else "ensure_proxy_health"
        if prefer_direct and outcome == "needs_prefer_direct_confirm":
            event = "prefer_direct_blocked"
        append_custody_event(
            event,
            actor="ensure_proxy_health",
            subsystem="ensure_proxy_health",
            dry_run=dry_run,
            confirmation_supplied=bool(prefer_direct and confirm == CONFIRM_PREFER_DIRECT and not dry_run),
            before=before if isinstance(before, dict) else None,
            after=final if isinstance(final, dict) else None,
            outcome=outcome,
            limitations=list(result["limitations"]),
            extra={"prefer_direct": prefer_direct, "observability_installed": result["observability_installed"]},
            soft_fail=True,
        )
    except Exception:
        # Custody must not break ensure / remediation paths (disk, TypeError, import).
        pass
    return result


def _recommend(outcome: str, prefer_direct: bool, dns: dict[str, Any] | None = None) -> str:
    if dns and dns.get("primary_off_subnet"):
        return (
            "DNS primary appears off-subnet (browser DNS_PROBE_FINISHED_BAD_CONFIG risk). "
            "Run .\\fix-dns.cmd elevated, then refresh the browser."
        )
    if outcome == "healthy":
        return "Proxy path clean. Restart LinkedIn/browser if they still show ERR_PROXY_CONNECTION_FAILED."
    if outcome == "still_dead":
        return "Still dead — run scripts/fix-wininet-proxy.cmd or proxy-fix with DISABLE_WININET_PROXY."
    if outcome == "localhost_proxy_broken":
        return (
            "Active-but-broken localhost proxy (listener up, path probe failed, direct ok). "
            f"Re-run with --confirm {CONFIRM_PREFER_DIRECT} (or --prefer-direct) to clear."
        )
    if outcome == "needs_prefer_direct_confirm":
        return (
            f"Localhost proxy still needs clear confirmation. Re-run with --confirm {CONFIRM_PREFER_DIRECT} "
            "(add --prefer-direct to clear a healthy active localhost proxy)."
        )
    if outcome == "localhost_proxy_active" and not prefer_direct:
        return (
            "Localhost proxy is active and path probe did not mark it broken. For LinkedIn reliability, run: "
            f"python -m src ensure-proxy-health --prefer-direct --confirm {CONFIRM_PREFER_DIRECT}"
        )
    if outcome == "would_remediate":
        return "Dry-run: dead or broken localhost proxy would be cleared; re-run without --dry-run to apply."
    return "Review ensure-proxy-health JSON output and limitations."
