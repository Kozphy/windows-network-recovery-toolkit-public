"""Dead / active-but-broken / hold-direct localhost proxy guardian with confirmation gates."""

from __future__ import annotations

import socket
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.logging.audit import append_jsonl
from src.proxy_drift.classify import classify_proxy_drift
from src.proxy_drift.proxy_fix import apply_proxy_fix
from src.proxy_guard.parser import parse_proxy_server
from src.proxy_guard.registry import read_proxy_registry

CONFIRM_CLEAR_DEAD = "CLEAR_DEAD_LOCALHOST_PROXY"
# Same token as ensure/auto-fix prefer-direct — clears listener-up path failures
# and (when hold_direct) any enabled localhost WinINET rewrite.
CONFIRM_CLEAR_BROKEN = "PREFER_DIRECT_WININET"
CONFIRM_HOLD_DIRECT = CONFIRM_CLEAR_BROKEN
_SCHEMA = "proxy_guardian.v1"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _port_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.35):
            return True
    except OSError:
        return False


def _listener_fingerprint(port: int | None) -> dict[str, Any]:
    """Best-effort read-only listener PID snapshot (correlation, not writer proof)."""
    if not port:
        return {}
    try:
        completed = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    needle = f":{int(port)}"
    pid: int | None = None
    for line in (completed.stdout or "").splitlines():
        if "LISTENING" not in line.upper():
            continue
        if needle not in line:
            continue
        # Prefer 127.0.0.1 / ::1 bindings.
        if "127.0.0.1" not in line and "[::1]" not in line and "0.0.0.0" not in line:
            continue
        parts = line.split()
        if not parts:
            continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        if pid > 0:
            break
    if not pid:
        return {"localhost_port": port}
    name = None
    try:
        # tasklist is read-only; avoids adding psutil as a hard dependency.
        tl = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        row = (tl.stdout or "").strip().splitlines()
        if row:
            # "name.exe","pid","session","session#","mem"
            cols = [c.strip().strip('"') for c in row[0].split(",")]
            if cols:
                name = cols[0]
    except (OSError, subprocess.TimeoutExpired):
        name = None
    out: dict[str, Any] = {"listener_pid": pid, "localhost_port": port}
    if name:
        out["listener_name"] = name
    return out


def _audit(log_path: Path, row: dict[str, Any]) -> None:
    """Dual-write: legacy JSONL under logs/ + hash-chained custody under WNT_AUDIT_DIR."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    append_jsonl(log_path, row)
    try:
        from src.platform_core.audit.custody import append_custody_event

        event = str(row.get("event") or "guardian_check")
        append_custody_event(
            event,
            actor="proxy_guardian",
            subsystem="proxy_guardian",
            dry_run=row.get("dry_run"),
            confirmation_supplied=bool(row.get("action_taken") == "remediated"),
            before={
                "proxy_enable": row.get("proxy_enable"),
                "proxy_server": row.get("proxy_server"),
            },
            after=None,
            outcome=str(row.get("action_taken") or ""),
            limitations=list(row.get("limitations") or []),
            extra={
                "classification": row.get("classification"),
                "dead_localhost_proxy": row.get("dead_localhost_proxy"),
                "broken_localhost_proxy": row.get("broken_localhost_proxy"),
                "hold_direct": row.get("hold_direct"),
                "reason": row.get("reason"),
                "listener_pid": row.get("listener_pid"),
                "listener_name": row.get("listener_name"),
            },
            soft_fail=True,
        )
    except Exception:
        # Custody must not break guardian remediation path.
        pass


def _assess_broken(
    *,
    enabled: bool,
    is_localhost: bool,
    port: int | None,
    listener: bool,
    path_health: dict[str, Any] | None,
) -> tuple[bool, dict[str, Any]]:
    """Return (is_broken, path_probe_dict) for listener-up path failures."""
    if not (enabled and is_localhost and port and listener):
        return False, {}
    # Lazy import avoids circular import with auto_fix → guardian.
    from src.proxy_drift.auto_fix import assess_localhost_proxy_path

    path = assess_localhost_proxy_path(int(port), inject=path_health)
    proxy_ok = path.get("proxy_probe_ok")
    direct_ok = path.get("direct_probe_ok")
    # Classic broken: proxy fail, direct ok.
    # Also treat proxy-fail + direct-fail as clearable when clear_broken is on:
    # system WinINET may poison casual probes; listener-up + failed proxy path is
    # enough for prefer-direct recurrence relief (not writer proof).
    broken = proxy_ok is False and direct_ok is not None
    return broken, path


def run_dead_proxy_guardian_once(
    *,
    dry_run: bool = True,
    confirm: str = "",
    clear_broken: bool = False,
    confirm_broken: str = "",
    hold_direct: bool = False,
    path_health: dict[str, Any] | None = None,
    audit_path: Path | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Check for dead, broken, or (opt-in) any localhost WinINET proxy; optionally clear.

    Dead (no listener) requires ``confirm == CLEAR_DEAD_LOCALHOST_PROXY``.

    Active-but-broken (listener up, proxy path fail) is checked when ``clear_broken``
    is true; live clear requires ``confirm_broken == PREFER_DIRECT_WININET``.

    Hold-direct (``hold_direct``) clears **any** enabled localhost WinINET proxy
    (including healthy tunnels) with the same prefer-direct token — for recurrence
    protection when the operator prefers direct browsing over local tunnels.
    """
    subprocess_run = run if run is not None else subprocess.run
    log_path = audit_path or Path("logs") / "proxy_guardian.jsonl"
    reg = read_proxy_registry(run=subprocess_run)
    parsed = parse_proxy_server(reg.proxy_server)
    enabled = int(reg.proxy_enable or 0) == 1
    port = parsed.localhost_port
    listener = _port_listening(int(port)) if port else False
    fingerprint = _listener_fingerprint(port if listener else None)

    broken = False
    path: dict[str, Any] = {}
    proxy_probe_ok: bool | None = None
    direct_probe_ok: bool | None = None
    need_path = (clear_broken or hold_direct) and enabled and parsed.is_localhost_proxy and port and listener
    if need_path and clear_broken:
        broken, path = _assess_broken(
            enabled=enabled,
            is_localhost=parsed.is_localhost_proxy,
            port=port,
            listener=listener,
            path_health=path_health,
        )
        raw_p = path.get("proxy_probe_ok")
        raw_d = path.get("direct_probe_ok")
        proxy_probe_ok = raw_p if isinstance(raw_p, bool) else None
        direct_probe_ok = raw_d if isinstance(raw_d, bool) else None

    classification = classify_proxy_drift(
        proxy_enable=reg.proxy_enable,
        proxy_server=reg.proxy_server,
        auto_config_url=reg.auto_config_url,
        listener_found=listener if port else None,
        proxy_probe_ok=proxy_probe_ok,
        direct_probe_ok=direct_probe_ok,
        process_name=fingerprint.get("listener_name"),
        command_line=fingerprint.get("listener_cmdline"),
    )
    label = classification["classification"]
    dead = bool(enabled and parsed.is_localhost_proxy and port and not listener)
    localhost_enabled = bool(enabled and parsed.is_localhost_proxy and port)
    hold_hit = bool(hold_direct and localhost_enabled and not dead)
    # Prefer dead over broken/hold if somehow overlapping.
    if dead:
        broken = False
        hold_hit = False
    elif hold_hit:
        # Hold-direct supersedes broken-only path (same remediation token).
        broken = False

    limitations = list(classification.get("limitations") or [])
    if clear_broken:
        limitations.append(
            "clear_broken remediates listener-up cases where the proxy path probe failed; "
            "without --hold-direct, healthy active localhost (proxy path ok) is left alone."
        )
    if hold_direct:
        limitations.append(
            "hold_direct clears ANY enabled localhost WinINET proxy (including healthy tunnels); "
            "use only when prefer-direct browsing is the policy goal. "
            "Listener process fingerprint is correlation only — not registry-writer proof."
        )

    result: dict[str, Any] = {
        "schema_version": _SCHEMA,
        "timestamp_utc": _now(),
        "dry_run": dry_run,
        "classification": label,
        "dead_localhost_proxy": dead,
        "broken_localhost_proxy": broken,
        "hold_direct": hold_direct,
        "hold_direct_hit": hold_hit,
        "clear_broken": clear_broken,
        "proxy_enable": reg.proxy_enable,
        "proxy_server": reg.proxy_server,
        "localhost_port": port,
        "listener_found": listener,
        "proxy_probe_ok": proxy_probe_ok,
        "direct_probe_ok": direct_probe_ok,
        "proxy_status": path.get("proxy_status"),
        "action_taken": "none",
        "recommended_action": "No change required.",
        "limitations": limitations,
        **fingerprint,
    }

    if not dead and not broken and not hold_hit:
        if hold_direct:
            result["reason"] = "No localhost WinINET proxy to clear (hold-direct idle)."
        elif clear_broken:
            result["reason"] = "No dead or active-but-broken localhost proxy detected."
        else:
            result["reason"] = "No dead localhost proxy detected."
        _audit(log_path, {"event": "guardian_check", **result})
        return result

    if dead:
        result["recommended_action"] = (
            "Set ProxyEnable=0 and clear localhost ProxyServer (preview by default)."
        )
        required = CONFIRM_CLEAR_DEAD
        confirm_ok = confirm == CONFIRM_CLEAR_DEAD
        event_preview = "guardian_preview"
        event_blocked = "guardian_blocked"
        event_apply = "guardian_apply"
        preview_reason = "Dead localhost proxy detected; dry-run — no registry mutation."
        blocked_reason = f"Confirmation required: {CONFIRM_CLEAR_DEAD}"
    elif hold_hit:
        result["recommended_action"] = (
            f"Hold-direct: clear localhost WinINET rewrite (confirm {CONFIRM_HOLD_DIRECT})."
        )
        required = CONFIRM_HOLD_DIRECT
        confirm_ok = confirm_broken == CONFIRM_HOLD_DIRECT
        event_preview = "guardian_hold_direct_preview"
        event_blocked = "guardian_hold_direct_blocked"
        event_apply = "guardian_hold_direct_apply"
        preview_reason = (
            "Hold-direct: enabled localhost WinINET detected; dry-run — no registry mutation."
        )
        blocked_reason = f"Confirmation required: {CONFIRM_HOLD_DIRECT}"
    else:
        result["recommended_action"] = (
            "Clear active-but-broken / unusable localhost WinINET proxy "
            f"(confirm {CONFIRM_CLEAR_BROKEN})."
        )
        required = CONFIRM_CLEAR_BROKEN
        confirm_ok = confirm_broken == CONFIRM_CLEAR_BROKEN
        event_preview = "guardian_broken_preview"
        event_blocked = "guardian_broken_blocked"
        event_apply = "guardian_broken_apply"
        preview_reason = (
            "Active-but-broken localhost proxy detected; dry-run — no registry mutation."
        )
        blocked_reason = f"Confirmation required: {CONFIRM_CLEAR_BROKEN}"

    if dry_run:
        result["action_taken"] = "preview_only"
        result["reason"] = preview_reason
        result["confirmation_required"] = required
        _audit(log_path, {"event": event_preview, **result})
        return result

    if not confirm_ok:
        result["action_taken"] = "blocked"
        result["reason"] = blocked_reason
        result["confirmation_required"] = required
        _audit(log_path, {"event": event_blocked, **result})
        return result

    fix = apply_proxy_fix(
        dry_run=False,
        confirm="DISABLE_WININET_PROXY",
        clear_pac=False,
        run=subprocess_run,
    )
    result["remediation"] = fix
    result["action_taken"] = "remediated" if fix.get("action_allowed") else "blocked"
    result["reason"] = fix.get("reason") or "Guardian remediation completed."
    if broken:
        result["cleared_broken_localhost"] = True
    if hold_hit:
        result["cleared_hold_direct"] = True
    _audit(log_path, {"event": event_apply, **result})
    return result


def run_dead_proxy_guardian_loop(
    *,
    interval_seconds: float = 60.0,
    once: bool = False,
    dry_run: bool = True,
    confirm: str = "",
    clear_broken: bool = False,
    confirm_broken: str = "",
    hold_direct: bool = False,
    audit_path: Path | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run guardian checks on an interval until interrupted or ``once``."""
    subprocess_run = run if run is not None else subprocess.run
    log_path = audit_path or Path("logs") / "proxy_guardian.jsonl"
    interval = max(1.0, interval_seconds)
    cycles = 0
    last: dict[str, Any] = {}
    while True:
        last = run_dead_proxy_guardian_once(
            dry_run=dry_run,
            confirm=confirm,
            clear_broken=clear_broken,
            confirm_broken=confirm_broken,
            hold_direct=hold_direct,
            audit_path=log_path,
            run=subprocess_run,
        )
        cycles += 1
        if once:
            break
        time.sleep(interval)
    return {"cycles": cycles, "last_result": last}
