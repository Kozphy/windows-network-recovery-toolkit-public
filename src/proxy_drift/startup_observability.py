"""Combined startup observability install/uninstall orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.proxy_drift.boot_trace_task import (
    install_boot_trace_task,
    preview_install_boot_trace_task,
    uninstall_boot_trace_task,
)
from src.proxy_drift.guardian_task import (
    install_guardian_task,
    preview_install_guardian_task,
    uninstall_guardian_task,
)

CONFIRM_INSTALL = "INSTALL_STARTUP_OBSERVABILITY"
CONFIRM_UNINSTALL = "UNINSTALL_STARTUP_OBSERVABILITY"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def preview_install_startup_observability(*, guardian_interval: int = 60, boot_duration: int = 180, boot_interval: int = 2) -> dict[str, Any]:
    """Build the combined startup observability install preview.

    Args:
        guardian_interval: Guardian loop interval in seconds.
        boot_duration: Boot trace duration in seconds.
        boot_interval: Boot trace sampling interval in seconds.

    Returns:
        Dict containing guardian and boot-trace previews plus confirmation requirements.

    Side effects:
        None.

    Audit Notes:
        Preview output does not create scheduled tasks or Startup hooks."""
    return {
        "schema_version": "startup_observability.v1",
        "timestamp_utc": _now(),
        "confirmation_required": CONFIRM_INSTALL,
        "components": {
            "guardian": preview_install_guardian_task(interval=guardian_interval),
            "boot_trace": preview_install_boot_trace_task(duration=boot_duration, interval=boot_interval),
        },
        "limitations": [
            "Install preview does not create scheduled tasks or Startup hooks.",
            "Boot trace is read-only; guardian only remediates dead localhost proxies.",
        ],
    }


def install_startup_observability(
    *,
    guardian_interval: int = 60,
    boot_duration: int = 180,
    boot_interval: int = 2,
    confirm: str = "",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Install guardian and boot-trace startup observability when confirmed.

    Args:
        guardian_interval: Guardian loop interval in seconds.
        boot_duration: Boot trace duration in seconds.
        boot_interval: Boot trace sampling interval in seconds.
        confirm: Required typed confirmation token.
        dry_run: When True, return preview-only output without installing.

    Returns:
        Dict summarizing component installation outcomes and action status.

    Side effects:
        When confirmed and not dry-run, may create scheduled tasks or Startup hook files.

    Audit Notes:
        Installation is policy-gated by ``INSTALL_STARTUP_OBSERVABILITY`` and component-level confirmations."""
    preview = preview_install_startup_observability(
        guardian_interval=guardian_interval,
        boot_duration=boot_duration,
        boot_interval=boot_interval,
    )
    if dry_run:
        preview["action_taken"] = "preview_only"
        preview["reason"] = "Dry-run — startup observability not installed."
        return preview
    if confirm != CONFIRM_INSTALL:
        preview["action_taken"] = "blocked"
        preview["reason"] = f"Confirmation required: {CONFIRM_INSTALL}"
        return preview
    guardian = install_guardian_task(interval=guardian_interval, confirm="INSTALL_GUARDIAN_TASK", dry_run=False)
    boot_trace = install_boot_trace_task(duration=boot_duration, interval=boot_interval, confirm="INSTALL_BOOT_TRACE_TASK", dry_run=False)
    action_taken = "installed"
    if guardian.get("action_taken") == "failed" or boot_trace.get("action_taken") == "failed":
        action_taken = "partial" if any(c.get("action_taken") == "installed" for c in (guardian, boot_trace)) else "failed"
    return {
        "schema_version": "startup_observability.v1",
        "timestamp_utc": _now(),
        "components": {"guardian": guardian, "boot_trace": boot_trace},
        "action_taken": action_taken,
        "reason": "Startup observability configured." if action_taken == "installed" else "One or more components failed.",
    }


def uninstall_startup_observability(*, confirm: str = "", dry_run: bool = True) -> dict[str, Any]:
    """Uninstall guardian and boot-trace startup observability when confirmed.

    Args:
        confirm: Required typed confirmation token.
        dry_run: When True, return preview-only output without uninstalling.

    Returns:
        Dict summarizing component uninstall outcomes and action status.

    Side effects:
        When confirmed and not dry-run, may delete scheduled tasks and Startup hook files.

    Audit Notes:
        Removal is policy-gated by ``UNINSTALL_STARTUP_OBSERVABILITY``."""
    payload: dict[str, Any] = {
        "schema_version": "startup_observability.v1",
        "timestamp_utc": _now(),
        "confirmation_required": CONFIRM_UNINSTALL,
    }
    if dry_run:
        payload["action_taken"] = "preview_only"
        payload["reason"] = "Dry-run — startup observability not removed."
        return payload
    if confirm != CONFIRM_UNINSTALL:
        payload["action_taken"] = "blocked"
        payload["reason"] = f"Confirmation required: {CONFIRM_UNINSTALL}"
        return payload
    guardian = uninstall_guardian_task(confirm="UNINSTALL_GUARDIAN_TASK", dry_run=False)
    boot_trace = uninstall_boot_trace_task(confirm="UNINSTALL_BOOT_TRACE_TASK", dry_run=False)
    payload["components"] = {"guardian": guardian, "boot_trace": boot_trace}
    payload["action_taken"] = "uninstalled" if all(
        c.get("action_taken") != "failed" for c in (guardian, boot_trace)
    ) else "partial"
    payload["reason"] = "Startup observability artifacts removed."
    return payload
