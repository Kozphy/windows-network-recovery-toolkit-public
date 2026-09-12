"""One-shot dead / active-but-broken localhost proxy auto-fix and optional guardian install."""

from __future__ import annotations

import platform
import socket
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.proxy_drift.classify import classify_proxy_drift
from src.proxy_drift.guardian import CONFIRM_CLEAR_DEAD, run_dead_proxy_guardian_once
from src.proxy_drift.proxy_fix import apply_proxy_fix
from src.proxy_guard.parser import parse_proxy_server
from src.proxy_guard.registry import read_proxy_registry
from src.proxy_guard.remediation import CONFIRMATION_PHRASE

_DEAD_CLASSIFICATIONS = frozenset(
    {
        "STALE_LOCALHOST_PROXY",
        "STALE_PROXY_AFTER_PROCESS_EXIT",
        "DEAD_PROXY_CONFIG",
    }
)
_BROKEN_CLASSIFICATIONS = frozenset({"BROKEN_LOCALHOST_PROXY"})
_SCHEMA = "auto_fix_proxy.v1"
_PATH_PROBE_TIMEOUT = 3.0

PathHealthFn = Callable[..., dict[str, Any]]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _port_listening(port: int | None) -> bool | None:
    if port is None:
        return None
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=0.35):
            return True
    except OSError:
        return False


def assess_localhost_proxy_path(
    port: int,
    *,
    inject: dict[str, Any] | None = None,
    timeout_seconds: float = _PATH_PROBE_TIMEOUT,
) -> dict[str, Any]:
    """Probe localhost proxy path vs direct HTTPS (read-only).

    Returns flags compatible with ``classify_proxy_drift`` and status dicts.
    ``inject`` short-circuits network I/O for deterministic tests.
    """
    if inject is not None:
        return {
            "proxy_probe_ok": inject.get("proxy_probe_ok"),
            "direct_probe_ok": inject.get("direct_probe_ok"),
            "proxy_status": inject.get("proxy_status"),
            "tcp_connect_ok": inject.get("tcp_connect_ok"),
            "probed": True,
            "injected": True,
        }

    try:
        from windows_network_toolkit.proxy_health import check_localhost_proxy_health
    except ImportError as exc:
        return {
            "proxy_probe_ok": None,
            "direct_probe_ok": None,
            "proxy_status": None,
            "tcp_connect_ok": None,
            "probed": False,
            "error": f"proxy_health unavailable: {exc}",
        }

    result = check_localhost_proxy_health(
        "127.0.0.1",
        int(port),
        timeout_seconds=timeout_seconds,
    )
    return {
        "proxy_probe_ok": bool(result.proxy_probe_ok),
        "direct_probe_ok": bool(result.direct_probe_ok),
        "proxy_status": result.proxy_status,
        "tcp_connect_ok": bool(result.tcp_connect_ok),
        "probed": True,
        "injected": False,
    }


def read_proxy_drift_status(
    *,
    run: Callable[..., Any] | None = None,
    path_health: dict[str, Any] | None = None,
    path_health_fn: PathHealthFn | None = None,
    skip_path_probe: bool = False,
) -> dict[str, Any]:
    """Return current WinINET proxy drift classification (read-only).

    When a localhost listener is present, runs a short proxy-vs-direct path probe
    unless ``skip_path_probe`` is set or ``path_health`` inject is supplied.
    """
    subprocess_run = run if run is not None else subprocess.run
    reg = read_proxy_registry(run=subprocess_run)
    parsed = parse_proxy_server(reg.proxy_server)
    listener = _port_listening(parsed.localhost_port)

    path: dict[str, Any] = {}
    proxy_probe_ok: bool | None = None
    direct_probe_ok: bool | None = None
    if listener is True and parsed.localhost_port is not None and not skip_path_probe:
        if path_health is not None:
            path = assess_localhost_proxy_path(int(parsed.localhost_port), inject=path_health)
        elif path_health_fn is not None:
            path = path_health_fn(int(parsed.localhost_port))
        else:
            path = assess_localhost_proxy_path(int(parsed.localhost_port))
        raw_proxy_ok = path.get("proxy_probe_ok")
        raw_direct_ok = path.get("direct_probe_ok")
        proxy_probe_ok = raw_proxy_ok if isinstance(raw_proxy_ok, bool) else None
        direct_probe_ok = raw_direct_ok if isinstance(raw_direct_ok, bool) else None

    classification = classify_proxy_drift(
        proxy_enable=reg.proxy_enable,
        proxy_server=reg.proxy_server,
        auto_config_url=reg.auto_config_url,
        listener_found=listener,
        proxy_probe_ok=proxy_probe_ok,
        direct_probe_ok=direct_probe_ok,
    )
    label = str(classification.get("classification") or "")
    legacy = label
    if label in {"STALE_LOCALHOST_PROXY", "STALE_PROXY_AFTER_PROCESS_EXIT"}:
        legacy = "DEAD_PROXY_CONFIG"
    elif label == "BROKEN_LOCALHOST_PROXY":
        legacy = "DEAD_PROXY_CONFIG"
    enabled = int(reg.proxy_enable or 0) == 1
    if not enabled and not parsed.raw:
        legacy = "NO_PROXY"

    limitations = list(classification.get("limitations") or [])
    if path.get("probed"):
        limitations.append(
            "Path probe contrasts proxied HTTPS vs direct; success does not prove proxy safety or intent."
        )

    return {
        "timestamp_utc": _now(),
        "classification": label,
        "legacy_classification": legacy,
        "is_dead_localhost_proxy": label in _DEAD_CLASSIFICATIONS,
        "is_broken_localhost_proxy": label in _BROKEN_CLASSIFICATIONS,
        "proxy_enable": reg.proxy_enable,
        "proxy_server": reg.proxy_server,
        "localhost_port": parsed.localhost_port,
        "listener_found": listener,
        "proxy_probe_ok": proxy_probe_ok,
        "direct_probe_ok": direct_probe_ok,
        "proxy_status": path.get("proxy_status"),
        "path_probe": path or None,
        "limitations": limitations,
    }


def _run_cursor_no_proxy_script(repo_root: Path, run: Callable[..., Any]) -> dict[str, Any]:
    script = repo_root / "scripts" / "configure-cursor-no-proxy.ps1"
    if not script.is_file():
        return {"step": "cursor_no_proxy", "skipped": True, "reason": "script missing"}
    proc = run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(repo_root),
    )
    return {
        "step": "cursor_no_proxy",
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "").strip()[-2000:],
        "stderr": (proc.stderr or "").strip()[-2000:],
    }


def _install_guardian_loop(
    repo_root: Path,
    *,
    interval_seconds: int,
    run: Callable[..., Any],
) -> dict[str, Any]:
    script = repo_root / "scripts" / "install-dead-proxy-guardian.ps1"
    if not script.is_file():
        return {"step": "guardian_install", "skipped": True, "reason": "installer missing"}
    interval_seconds = max(5, int(interval_seconds))
    proc = run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-IntervalSeconds",
            str(interval_seconds),
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(repo_root),
    )
    return {
        "step": "guardian_install",
        "interval_seconds": interval_seconds,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "").strip()[-3000:],
        "stderr": (proc.stderr or "").strip()[-2000:],
    }


def _prefer_direct_clear(
    *,
    dry_run: bool,
    confirm: str,
    confirm_token: str,
    status: dict[str, Any],
    reason_preview: str,
    run: Callable[..., Any],
) -> dict[str, Any]:
    if dry_run:
        return {
            "action_taken": "preview_only",
            "reason": reason_preview,
            "proxy_server": status.get("proxy_server"),
            "classification": status.get("classification"),
        }
    if confirm != confirm_token:
        return {
            "action_taken": "blocked",
            "reason": f"Confirmation required: {confirm_token}",
            "proxy_server": status.get("proxy_server"),
            "classification": status.get("classification"),
        }
    prefer_result = apply_proxy_fix(
        dry_run=False,
        confirm=CONFIRMATION_PHRASE,
        clear_pac=False,
        run=run,
    )
    prefer_result["prefer_direct"] = True
    prefer_result["cleared_broken_localhost"] = bool(status.get("is_broken_localhost_proxy"))
    return prefer_result


def run_auto_fix_proxy(
    *,
    dry_run: bool = False,
    skip_guardian_install: bool = False,
    skip_cursor_fix: bool = False,
    guardian_interval_seconds: int = 15,
    prefer_direct: bool = False,
    confirm: str = "",
    repo_root: Path | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Clear dead or active-but-broken localhost WinINET proxy; optional guardian install.

    Default path clears **dead** (no-listener) proxies via guardian / proxy-fix.

    Active-but-broken (listener up, proxy path fail, direct HTTPS ok) uses the same
    ``PREFER_DIRECT_WININET`` confirm gate as ``prefer_direct`` — clear when confirm
    matches, even without ``--prefer-direct``. Healthy active localhost still requires
    ``prefer_direct`` plus confirm.
    """
    if platform.system() != "Windows":
        return {
            "schema_version": _SCHEMA,
            "unsupported_platform": True,
            "platform": platform.system(),
            "outcome": "unsupported",
        }

    from src.proxy_drift.ensure_health import CONFIRM_PREFER_DIRECT

    subprocess_run = run if run is not None else subprocess.run
    repo = (repo_root or Path.cwd()).resolve()
    steps: list[dict[str, Any]] = []

    if not skip_cursor_fix and not dry_run:
        steps.append(_run_cursor_no_proxy_script(repo, subprocess_run))

    before = read_proxy_drift_status(run=subprocess_run)
    steps.append({"step": "status_before", "result": before})

    guardian = run_dead_proxy_guardian_once(
        dry_run=dry_run,
        confirm=CONFIRM_CLEAR_DEAD if not dry_run else "",
        run=subprocess_run,
    )
    steps.append({"step": "proxy_guardian", "result": guardian})

    after_guardian = read_proxy_drift_status(run=subprocess_run)
    steps.append({"step": "status_after_guardian", "result": after_guardian})

    fix_result: dict[str, Any] | None = None
    if after_guardian.get("is_dead_localhost_proxy") and not dry_run:
        fix_result = apply_proxy_fix(
            dry_run=False,
            confirm=CONFIRMATION_PHRASE,
            clear_pac=False,
            run=subprocess_run,
        )
        steps.append({"step": "proxy_fix_fallback", "result": fix_result})

    prefer_result: dict[str, Any] | None = None
    after_dead = read_proxy_drift_status(run=subprocess_run)
    localhost_enabled = (
        int(after_dead.get("proxy_enable") or 0) == 1 and after_dead.get("localhost_port") is not None
    )
    broken = bool(after_dead.get("is_broken_localhost_proxy"))
    # Broken path clears with prefer-direct confirm; healthy active needs prefer_direct flag.
    should_prefer_clear = localhost_enabled and (prefer_direct or broken)
    if should_prefer_clear:
        reason = (
            f"Would clear active-but-broken localhost WinINET proxy (confirm {CONFIRM_PREFER_DIRECT})."
            if broken
            else f"Would clear active localhost WinINET proxy (confirm {CONFIRM_PREFER_DIRECT})."
        )
        prefer_result = _prefer_direct_clear(
            dry_run=dry_run,
            confirm=confirm,
            confirm_token=CONFIRM_PREFER_DIRECT,
            status=after_dead,
            reason_preview=reason,
            run=subprocess_run,
        )
        steps.append({"step": "prefer_direct", "result": prefer_result})

    final = read_proxy_drift_status(run=subprocess_run)
    steps.append({"step": "status_final", "result": final})

    if not skip_guardian_install and not dry_run:
        steps.append(
            _install_guardian_loop(
                repo,
                interval_seconds=guardian_interval_seconds,
                run=subprocess_run,
            )
        )

    final_localhost = (
        int(final.get("proxy_enable") or 0) == 1 and final.get("localhost_port") is not None
    )
    final_broken = bool(final.get("is_broken_localhost_proxy"))
    prefer_blocked = bool(
        prefer_result and prefer_result.get("action_taken") == "blocked"
    )
    if final.get("is_dead_localhost_proxy"):
        outcome = "would_remediate" if dry_run else "still_dead"
    elif final_broken and prefer_blocked:
        outcome = "needs_prefer_direct_confirm"
    elif final_broken:
        outcome = "would_remediate" if dry_run else "localhost_proxy_broken"
    elif prefer_direct and localhost_enabled and prefer_blocked:
        outcome = "needs_prefer_direct_confirm"
    elif final_localhost:
        outcome = "localhost_proxy_active"
    else:
        outcome = "healthy"

    return {
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
        "steps": steps,
        "limitations": [
            "Default auto-fix clears dead localhost WinINET proxy only — not corporate proxy policy.",
            "Active-but-broken (listener up, proxy path fail, direct ok) clears with PREFER_DIRECT_WININET.",
            "prefer_direct also clears healthy active localhost proxies; may break intentional local tunnels.",
            "Listener correlation is not registry writer proof.",
            "Background guardian only remediates dead (no-listener) proxies — not broken-listener cases.",
        ],
    }
