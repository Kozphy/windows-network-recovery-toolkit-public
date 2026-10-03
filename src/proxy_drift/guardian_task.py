"""Install/uninstall WNRT-DeadProxyGuardian scheduled task at user logon."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.proxy_drift.startup_hook import remove_startup_hook, startup_hook_path, write_startup_hook

TASK_NAME = "WNRT-DeadProxyGuardian"
CONFIRM_INSTALL = "INSTALL_GUARDIAN_TASK"
CONFIRM_UNINSTALL = "UNINSTALL_GUARDIAN_TASK"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _python_exe() -> str:
    return sys.executable


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_guardian_task_command(*, interval: int = 60) -> str:
    """Return the command line the scheduled task should execute."""
    py = _python_exe()
    runner = _repo_root() / "scripts" / "run_src.py"
    return (
        f'"{py}" "{runner}" proxy-guardian --loop --interval {interval} '
        f"--confirm CLEAR_DEAD_LOCALHOST_PROXY "
        f"--clear-broken --hold-direct --confirm-broken PREFER_DIRECT_WININET --dry-run false"
    )


def build_startup_hook_lines(*, interval: int = 60) -> list[str]:
    """Build Startup-folder command lines for the guardian fallback.

    Args:
        interval: Guardian loop interval in seconds.

    Returns:
        Lines for a ``.cmd`` Startup hook that launches the guardian loop.

    Side effects:
        Resolves repository script paths; does not write files.

    Audit Notes:
        The generated command still relies on the guardian's typed confirmations and policy gates."""
    repo_root = _repo_root()
    loop_script = repo_root / "scripts" / "run-proxy-guardian-loop.ps1"
    return [
        "@echo off",
        f'cd /d "{repo_root}"',
        f"set PYTHONPATH={repo_root}",
        (
            "start /min powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden "
            f'-File "{loop_script}" -IntervalSeconds {interval}'
        ),
    ]


def build_schtasks_create_preview(*, interval: int = 60) -> tuple[str, ...]:
    """Return argv for ``schtasks /Create`` (preview only)."""
    cmd = build_guardian_task_command(interval=interval)
    return (
        "schtasks",
        "/Create",
        "/TN",
        TASK_NAME,
        "/SC",
        "ONLOGON",
        "/RL",
        "LIMITED",
        "/F",
        "/TR",
        cmd,
    )


def preview_install_guardian_task(*, interval: int = 60) -> dict[str, Any]:
    """Return human-readable preview of the scheduled task without creating it."""
    argv = build_schtasks_create_preview(interval=interval)
    return {
        "schema_version": "guardian_task.v1",
        "timestamp_utc": _now(),
        "task_name": TASK_NAME,
        "requested_method": "scheduled_task",
        "fallback_method": "startup_hook",
        "trigger": "ONLOGON",
        "command": build_guardian_task_command(interval=interval),
        "schtasks_argv": list(argv),
        "schtasks_command": subprocess.list2cmdline(list(argv)),
        "startup_hook_path": str(startup_hook_path(TASK_NAME).resolve()),
        "verify_commands": {
            "scheduled_task": f"schtasks /Query /TN {TASK_NAME}",
            "startup_hook": str(startup_hook_path(TASK_NAME).resolve()),
        },
        "confirmation_required": CONFIRM_INSTALL,
        "limitations": [
            "Task creation mutates Windows scheduler — preview shown first.",
            "Guardian only clears dead localhost proxies with typed confirmation.",
        ],
    }


def install_guardian_task(
    *,
    interval: int = 60,
    confirm: str = "",
    dry_run: bool = True,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Create logon scheduled task when confirmed, falling back to Startup hook."""
    subprocess_run = run if run is not None else subprocess.run
    preview = preview_install_guardian_task(interval=interval)
    if dry_run:
        preview["action_taken"] = "preview_only"
        preview["reason"] = "Dry-run — task not created."
        return preview
    if confirm != CONFIRM_INSTALL:
        preview["action_taken"] = "blocked"
        preview["reason"] = f"Confirmation required: {CONFIRM_INSTALL}"
        return preview
    argv = tuple(preview["schtasks_argv"])
    proc = subprocess_run(argv, capture_output=True, text=True, timeout=60, shell=False)
    preview["returncode"] = proc.returncode
    preview["stdout"] = (proc.stdout or "").strip()
    preview["stderr"] = (proc.stderr or "").strip()
    if proc.returncode == 0:
        preview["actual_method"] = "scheduled_task"
        preview["fallback_used"] = False
        preview["action_taken"] = "installed"
        preview["reason"] = "Scheduled task created."
        return preview
    stderr_l = (proc.stderr or "").lower()
    stdout_l = (proc.stdout or "").lower()
    if "access is denied" in stderr_l or "access is denied" in stdout_l:
        hook = write_startup_hook(name=TASK_NAME, lines=build_startup_hook_lines(interval=interval))
        preview["actual_method"] = "startup_hook"
        preview["fallback_used"] = True
        preview["startup_hook_path"] = str(hook.resolve())
        preview["action_taken"] = "installed"
        preview["reason"] = "Scheduled task denied; Startup hook installed."
        return preview
    preview["actual_method"] = None
    preview["fallback_used"] = False
    preview["action_taken"] = "failed"
    preview["reason"] = "schtasks failed."
    return preview


def uninstall_guardian_task(
    *,
    confirm: str = "",
    dry_run: bool = True,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Remove the guardian scheduled task and Startup hook when confirmed."""
    subprocess_run = run if run is not None else subprocess.run
    argv = ("schtasks", "/Delete", "/TN", TASK_NAME, "/F")
    payload: dict[str, Any] = {
        "schema_version": "guardian_task.v1",
        "timestamp_utc": _now(),
        "task_name": TASK_NAME,
        "requested_method": "all",
        "schtasks_argv": list(argv),
        "schtasks_command": subprocess.list2cmdline(list(argv)),
        "startup_hook_path": str(startup_hook_path(TASK_NAME).resolve()),
        "confirmation_required": CONFIRM_UNINSTALL,
    }
    if dry_run:
        payload["action_taken"] = "preview_only"
        payload["reason"] = "Dry-run — task not deleted."
        return payload
    if confirm != CONFIRM_UNINSTALL:
        payload["action_taken"] = "blocked"
        payload["reason"] = f"Confirmation required: {CONFIRM_UNINSTALL}"
        return payload
    proc = subprocess_run(argv, capture_output=True, text=True, timeout=60, shell=False)
    hook_removed = remove_startup_hook(TASK_NAME)
    payload["returncode"] = proc.returncode
    payload["stdout"] = (proc.stdout or "").strip()
    payload["stderr"] = (proc.stderr or "").strip()
    payload["startup_hook_removed"] = hook_removed
    if (
        proc.returncode == 0
        or hook_removed
        or "cannot find the file specified" in (proc.stderr or "").lower()
    ):
        payload["action_taken"] = "uninstalled"
        payload["reason"] = "Startup observability artifacts removed."
    else:
        payload["action_taken"] = "failed"
        payload["reason"] = "schtasks delete failed."
    return payload
