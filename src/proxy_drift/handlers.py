"""CLI handlers for ``python -m src`` proxy drift commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.core.windows_cli import exit_code_if_not_windows
from src.proxy_drift.boot_trace import run_boot_trace_loop
from src.proxy_drift.boot_trace_task import (
    install_boot_trace_task,
    preview_install_boot_trace_task,
    uninstall_boot_trace_task,
)
from src.proxy_drift.evidence_bundle import collect_evidence_bundle
from src.proxy_drift.guardian import run_dead_proxy_guardian_loop, run_dead_proxy_guardian_once
from src.proxy_drift.guardian_task import (
    install_guardian_task,
    preview_install_guardian_task,
    uninstall_guardian_task,
)
from src.proxy_drift.proxy_fix import apply_proxy_fix
from src.proxy_drift.safe_search import safe_search
from src.proxy_drift.startup_inventory import collect_startup_inventory, format_startup_table
from src.proxy_drift.startup_observability import (
    install_startup_observability,
    preview_install_startup_observability,
    uninstall_startup_observability,
)
from src.proxy_drift.startup_observability_report import summarize_boot_trace


def _print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_startup_inventory(args: argparse.Namespace) -> int:
    """Targeted startup inventory (no full profile recursion)."""
    if (code := exit_code_if_not_windows("startup-inventory")) is not None:
        return code
    repo = Path.cwd()
    audit = repo / "logs" / "startup_inventory.jsonl"
    payload = collect_startup_inventory(repo_root=repo, audit_path=audit)
    if getattr(args, "emit_json", False):
        _print_json(payload)
    else:
        print(format_startup_table(payload))
        print(f"Audit: {audit.resolve()}")
    return 0


def cmd_proxy_boot_trace(args: argparse.Namespace) -> int:
    """Post-login proxy boot trace with delta detection."""
    if (code := exit_code_if_not_windows("proxy-boot-trace")) is not None:
        return code
    result = run_boot_trace_loop(
        duration_seconds=float(args.boot_trace_duration),
        interval_seconds=float(args.boot_trace_interval),
    )
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Boot trace complete — {result.get('samples_collected')} samples")
        print(f"Audit: {result.get('audit_path')}")
    return 0


def cmd_install_boot_trace_task(args: argparse.Namespace) -> int:
    """Preview or install WNRT-ProxyBootTrace scheduled task."""
    if (code := exit_code_if_not_windows("install-boot-trace-task")) is not None:
        return code
    duration = int(getattr(args, "boot_trace_duration", 180))
    interval = int(getattr(args, "boot_trace_interval", 2))
    dry_run = bool(getattr(args, "dry_run", True))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    if dry_run and not confirm:
        result = preview_install_boot_trace_task(duration=duration, interval=interval)
    else:
        result = install_boot_trace_task(
            duration=duration,
            interval=interval,
            confirm=confirm,
            dry_run=dry_run,
        )
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Task: {result.get('task_name')}")
        print(f"Command: {result.get('command')}")
        print(f"schtasks: {result.get('schtasks_command')}")
        print(f"Action: {result.get('action_taken', 'preview')} — {result.get('reason', '')}")
        if result.get("confirmation_required"):
            print(f"Confirm with: --confirm {result['confirmation_required']} --dry-run false")
    return 0 if result.get("action_taken") != "failed" else 1


def cmd_uninstall_boot_trace_task(args: argparse.Namespace) -> int:
    """Preview or remove WNRT-ProxyBootTrace scheduled task."""
    if (code := exit_code_if_not_windows("uninstall-boot-trace-task")) is not None:
        return code
    dry_run = bool(getattr(args, "dry_run", True))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    result = uninstall_boot_trace_task(confirm=confirm, dry_run=dry_run)
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"schtasks: {result.get('schtasks_command')}")
        print(f"Action: {result.get('action_taken')} — {result.get('reason')}")
    return 0 if result.get("action_taken") != "failed" else 1


def cmd_install_startup_observability(args: argparse.Namespace) -> int:
    """Preview or install startup observability automation."""
    if (code := exit_code_if_not_windows("install-startup-observability")) is not None:
        return code
    guardian_interval = int(getattr(args, "guardian_interval", 15))
    boot_duration = int(getattr(args, "boot_trace_duration", 180))
    boot_interval = int(getattr(args, "boot_trace_interval", 2))
    dry_run = bool(getattr(args, "dry_run", True))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    if dry_run and not confirm:
        result = preview_install_startup_observability(
            guardian_interval=guardian_interval,
            boot_duration=boot_duration,
            boot_interval=boot_interval,
        )
    else:
        result = install_startup_observability(
            guardian_interval=guardian_interval,
            boot_duration=boot_duration,
            boot_interval=boot_interval,
            confirm=confirm,
            dry_run=dry_run,
        )
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Action: {result.get('action_taken')} — {result.get('reason')}")
        comps = result.get("components") or {}
        for name, comp in comps.items():
            print(f"{name}: {comp.get('action_taken')} ({comp.get('reason')})")
    return 0 if result.get("action_taken") not in {"failed"} else 1


def cmd_uninstall_startup_observability(args: argparse.Namespace) -> int:
    """Preview or uninstall startup observability automation."""
    if (code := exit_code_if_not_windows("uninstall-startup-observability")) is not None:
        return code
    dry_run = bool(getattr(args, "dry_run", True))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    result = uninstall_startup_observability(confirm=confirm, dry_run=dry_run)
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Action: {result.get('action_taken')} — {result.get('reason')}")
        comps = result.get("components") or {}
        for name, comp in comps.items():
            print(f"{name}: {comp.get('action_taken')} ({comp.get('reason')})")
    return 0 if result.get("action_taken") not in {"failed"} else 1


def cmd_proxy_guardian_drift(args: argparse.Namespace) -> int:
    """Dead / broken / hold-direct localhost proxy guardian (dry-run by default)."""
    if (code := exit_code_if_not_windows("proxy-guardian")) is not None:
        return code
    dry_run = bool(getattr(args, "dry_run", True))
    once = bool(getattr(args, "once", True)) and not bool(getattr(args, "guardian_loop", False))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    clear_broken = bool(getattr(args, "clear_broken", False))
    confirm_broken = str(getattr(args, "confirm_broken", "") or "")
    hold_direct = bool(getattr(args, "hold_direct", False))
    interval = float(getattr(args, "interval", 60.0))
    if once:
        result = run_dead_proxy_guardian_once(
            dry_run=dry_run,
            confirm=confirm,
            clear_broken=clear_broken,
            confirm_broken=confirm_broken,
            hold_direct=hold_direct,
        )
    else:
        result = run_dead_proxy_guardian_loop(
            interval_seconds=interval,
            once=False,
            dry_run=dry_run,
            confirm=confirm,
            clear_broken=clear_broken,
            confirm_broken=confirm_broken,
            hold_direct=hold_direct,
        )
    display = result if once else result.get("last_result", result)
    if getattr(args, "emit_json", False):
        _print_json(display)
    else:
        print(f"Classification: {display.get('classification')}")
        print(
            f"Dead: {display.get('dead_localhost_proxy')} "
            f"Broken: {display.get('broken_localhost_proxy')} "
            f"HoldDirect: {display.get('hold_direct_hit')}"
        )
        print(f"Action: {display.get('action_taken')} — {display.get('reason')}")
        print("Audit: logs/proxy_guardian.jsonl")
    return 0


def cmd_install_guardian_task(args: argparse.Namespace) -> int:
    """Preview or install WNRT-DeadProxyGuardian scheduled task."""
    if (code := exit_code_if_not_windows("install-guardian-task")) is not None:
        return code
    interval = int(getattr(args, "interval", 60))
    dry_run = bool(getattr(args, "dry_run", True))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    if dry_run and not confirm:
        result = preview_install_guardian_task(interval=interval)
    else:
        result = install_guardian_task(interval=interval, confirm=confirm, dry_run=dry_run)
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Task: {result.get('task_name')}")
        print(f"Command: {result.get('command')}")
        print(f"schtasks: {result.get('schtasks_command')}")
        print(f"Action: {result.get('action_taken', 'preview')} — {result.get('reason', '')}")
        if result.get("confirmation_required"):
            print(f"Confirm with: --confirm {result['confirmation_required']} --dry-run false")
    return 0 if result.get("action_taken") != "failed" else 1


def cmd_uninstall_guardian_task(args: argparse.Namespace) -> int:
    """Preview or remove WNRT-DeadProxyGuardian scheduled task."""
    if (code := exit_code_if_not_windows("uninstall-guardian-task")) is not None:
        return code
    dry_run = bool(getattr(args, "dry_run", True))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    result = uninstall_guardian_task(confirm=confirm, dry_run=dry_run)
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"schtasks: {result.get('schtasks_command')}")
        print(f"Action: {result.get('action_taken')} — {result.get('reason')}")
    return 0 if result.get("action_taken") != "failed" else 1


def cmd_proxy_fix(args: argparse.Namespace) -> int:
    """Emergency HKCU WinINET proxy fix (localhost server clear only)."""
    if (code := exit_code_if_not_windows("proxy-fix")) is not None:
        return code
    dry_run = bool(getattr(args, "dry_run", True))
    confirm = str(getattr(args, "confirm_phrase", "") or "")
    clear_pac = bool(getattr(args, "clear_pac", False))
    result = apply_proxy_fix(dry_run=dry_run, confirm=confirm, clear_pac=clear_pac)
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        for line in result.get("planned_changes") or []:
            print(line)
        print(result.get("reason") or "")
    return 0 if result.get("action_allowed") or dry_run else 1


def cmd_safe_search(args: argparse.Namespace) -> int:
    """Timeout-safe targeted file search."""
    result = safe_search(
        query=str(getattr(args, "search_query", "") or ""),
        target=str(getattr(args, "search_target", "project") or "project"),
        repo_root=Path.cwd(),
        max_seconds=float(getattr(args, "search_max_seconds", 20.0)),
        max_files=int(getattr(args, "search_max_files", 3000)),
    )
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Scanned {result['scanned_files']} files — {result['match_count']} matches")
        if result.get("timed_out"):
            print("(stopped: timeout or file cap)")
        for row in result.get("matches") or []:
            print(row.get("path"))
    return 0


def cmd_collect_evidence_bundle(args: argparse.Namespace) -> int:
    """Collect a read-only evidence bundle for proxy/network issues."""
    if (code := exit_code_if_not_windows("collect-evidence-bundle")) is not None:
        return code
    repo_root = Path.cwd()
    bundle_dir_arg = getattr(args, "bundle_dir", None)
    result = collect_evidence_bundle(
        repo_root=repo_root,
        bundle_dir=Path(bundle_dir_arg).resolve() if bundle_dir_arg else None,
        boot_duration=int(getattr(args, "boot_trace_duration", 30)),
        boot_interval=int(getattr(args, "boot_trace_interval", 2)),
    )
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Bundle: {result.get('bundle_dir')}")
        print(f"Files written: {len(result.get('files_written') or [])}")
    return 0


def cmd_startup_observability_report(args: argparse.Namespace) -> int:
    """Summarize startup observability logs for operators."""
    trace_path_arg = str(getattr(args, "trace_path", "") or "")
    trace_path = Path(trace_path_arg) if trace_path_arg else Path.cwd() / "logs" / "proxy_boot_trace.jsonl"
    result = summarize_boot_trace(trace_path.resolve())
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Samples: {result.get('samples')}")
        print(f"Final classification: {result.get('final_classification')}")
        print(f"Final proxy: {result.get('final_proxy_server')}")
        print(f"Delta events: {', '.join(result.get('delta_events_seen') or []) or '(none)'}")
        print(result.get("recommended_next_step") or "")
    return 0


def cmd_auto_fix_proxy(args: argparse.Namespace) -> int:
    """One-shot dead localhost proxy auto-fix + guardian install."""
    if (code := exit_code_if_not_windows("auto-fix-proxy")) is not None:
        return code
    from src.proxy_drift.auto_fix import run_auto_fix_proxy

    dry_run = bool(getattr(args, "dry_run", False))
    result = run_auto_fix_proxy(
        dry_run=dry_run,
        skip_guardian_install=bool(getattr(args, "skip_guardian_install", False)),
        skip_cursor_fix=bool(getattr(args, "skip_cursor_fix", False)),
        guardian_interval_seconds=int(getattr(args, "guardian_interval", 15)),
        prefer_direct=bool(getattr(args, "prefer_direct", False)),
        confirm=str(getattr(args, "confirm_phrase", "") or ""),
        repo_root=Path.cwd(),
    )
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Outcome: {result.get('outcome')}")
        print(f"Classification: {result.get('classification')} (legacy: {result.get('legacy_classification')})")
        if result.get("outcome") == "healthy":
            print("OK: Proxy path is clean. Restart your browser.")
        elif result.get("outcome") == "still_dead":
            print("WARN: Still dead — try scripts/fix-wininet-proxy.cmd")
        elif result.get("outcome") == "localhost_proxy_broken":
            print(
                "WARN: Active-but-broken localhost proxy (listener up, path failed, direct ok). "
                "Re-run with --confirm PREFER_DIRECT_WININET"
            )
        elif result.get("outcome") == "localhost_proxy_active":
            print("WARN: Localhost proxy still active — re-run with --prefer-direct --confirm PREFER_DIRECT_WININET")
        elif result.get("outcome") == "needs_prefer_direct_confirm":
            print("WARN: prefer-direct blocked — supply --confirm PREFER_DIRECT_WININET")
        elif dry_run:
            print("Dry-run preview — no registry changes or guardian install.")
    outcome = str(result.get("outcome") or "")
    if outcome in {"still_dead", "needs_prefer_direct_confirm", "localhost_proxy_broken"}:
        return 1
    if outcome == "unsupported":
        return 2
    return 0


def cmd_ensure_proxy_health(args: argparse.Namespace) -> int:
    """Session ensure: dead-proxy fix + startup observability; optional prefer-direct."""
    if (code := exit_code_if_not_windows("ensure-proxy-health")) is not None:
        return code
    from src.proxy_drift.ensure_health import run_ensure_proxy_health

    dry_run = bool(getattr(args, "dry_run", False))
    result = run_ensure_proxy_health(
        dry_run=dry_run,
        prefer_direct=bool(getattr(args, "prefer_direct", False)),
        confirm=str(getattr(args, "confirm_phrase", "") or ""),
        skip_observability_install=bool(getattr(args, "skip_observability_install", False)),
        skip_cursor_fix=bool(getattr(args, "skip_cursor_fix", False)),
        guardian_interval_seconds=int(getattr(args, "guardian_interval", 15)),
        repo_root=Path.cwd(),
    )
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Outcome: {result.get('outcome')}")
        print(f"Classification: {result.get('classification')}")
        print(f"Proxy: enable={result.get('proxy_enable')} server={result.get('proxy_server')}")
        dns = result.get("dns_health") or {}
        if dns:
            print(
                f"DNS: {dns.get('classification')} primary={dns.get('primary_dns')} "
                f"servers={dns.get('dns_servers')}"
            )
        print(f"Observability installed: {result.get('observability_installed')}")
        print(result.get("recommended_next_step") or "")
    outcome = str(result.get("outcome") or "")
    dns = result.get("dns_health") or {}
    if outcome in {"still_dead", "needs_prefer_direct_confirm", "localhost_proxy_broken"}:
        return 1
    if outcome == "unsupported":
        return 2
    if dns.get("primary_off_subnet"):
        return 3
    return 0


def cmd_dns_health(args: argparse.Namespace) -> int:
    """Read-only Wi-Fi DNS health heuristic (DNS_PROBE_FINISHED_BAD_CONFIG triage)."""
    if (code := exit_code_if_not_windows("dns-health")) is not None:
        return code
    from src.proxy_drift.dns_health import collect_wifi_dns_snapshot

    alias = str(getattr(args, "interface_alias", "Wi-Fi") or "Wi-Fi")
    result = collect_wifi_dns_snapshot(interface_alias=alias)
    if getattr(args, "emit_json", False):
        _print_json(result)
    else:
        print(f"Classification: {result.get('classification')}")
        print(f"Interface: {result.get('interface_alias')} IPv4={result.get('interface_ipv4')}")
        print(f"Gateway: {result.get('gateway')}")
        print(f"DNS servers: {result.get('dns_servers')}")
        print(f"Primary off-subnet: {result.get('primary_off_subnet')}")
        print(result.get("recommended_action") or "")
        for lim in result.get("limitations") or []:
            print(f"Limitation: {lim}")
    return 3 if result.get("primary_off_subnet") else 0
