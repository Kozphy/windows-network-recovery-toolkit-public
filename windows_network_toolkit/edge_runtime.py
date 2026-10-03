"""Read-only Edge runtime health: frozen tabs, GPU-off, restart-pending, memory pressure.

Module responsibility:
    Sample ``msedge.exe`` processes twice a few seconds apart (CPU delta per process,
    process type from the command line), read free RAM and GPU adapters, and turn that
    into plain-language ``issues[]`` with a manual user action each. Also reports which
    extension IDs the HKCU ``ExtensionSettings`` policy already blocks and the most recent
    live Edge fix from the audit logs.

System placement:
    Called by ``edge_triage.triage_edge_loading`` (``edge-triage`` CLI). Pure analysis
    (``analyze_edge_runtime``) is separated from collection for fixture tests.

Key invariants:
    * Read-only: never ends a process, writes policy, or edits Edge files. Frozen tabs
      are reported with a manual "End process" step for the user.
    * CPU sampling is a short window — a busy tab is a correlation with "This page isn't
      responding", not proof of which site froze.

Side effects:
    One PowerShell invocation (Get-Process / CIM reads, sleeps ``sample_seconds``), a
    ``reg query`` via ``edge_extension_policy.read_extension_settings``, and audit reads.

Failure modes:
    Non-Windows or PowerShell failure → ``sample_edge_processes`` returns ``None`` and
    the analysis reports ``sampled: False`` with no issues.
"""

from __future__ import annotations

import json
import platform
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from windows_network_toolkit.audit_store import audit_dir

DEFAULT_SAMPLE_SECONDS = 3.0
HUNG_CORE_FRACTION = 0.8
LOW_FREE_RAM_MB = 2048
LOW_FREE_RAM_FRACTION = 0.10
_AUDIT_TAIL_LINES = 500
_SEVERITY_ORDER = {"high": 0, "medium": 1}
_CAPABLE_GPU_MARKERS = ("nvidia", "radeon rx", "arc(tm)", "intel(r) arc")

RUNTIME_LIMITATIONS = [
    "CPU sample covers a few seconds; a busy tab correlates with a hang but does not name the site.",
    "Toolkit never ends Edge processes; frozen tabs need the user's Exit page / End process.",
]

_PS_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$cmd = @{}
Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | ForEach-Object { $cmd[[int]$_.ProcessId] = [string]$_.CommandLine }
$before = @{}
Get-Process msedge | ForEach-Object { $before[$_.Id] = $_.CPU }
Start-Sleep -Milliseconds __MS__
$rows = @(Get-Process msedge | ForEach-Object {
  $cl = $cmd[$_.Id]
  $type = if ($cl -match '--type=([\w-]+)') { $matches[1] } else { 'browser' }
  [pscustomobject]@{
    pid = $_.Id
    type = $type
    extension = [bool]($cl -match '--extension-process')
    gpu_disabled_flag = [bool]($cl -match '--disable-gpu(\s|$|-compositing)|--use-gl=disabled|swiftshader')
    cpu_seconds = if ($before.ContainsKey($_.Id)) { [math]::Round($_.CPU - $before[$_.Id], 2) } else { 0 }
    mb = [math]::Round($_.WorkingSet64 / 1MB)
    start_utc = $_.StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  }
})
$os = Get-CimInstance Win32_OperatingSystem
[pscustomobject]@{
  processes = $rows
  free_mb = [math]::Round($os.FreePhysicalMemory / 1KB)
  total_mb = [math]::Round($os.TotalVisibleMemorySize / 1KB)
  gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name })
} | ConvertTo-Json -Depth 4 -Compress
"""


def sample_edge_processes(
    sample_seconds: float = DEFAULT_SAMPLE_SECONDS,
    *,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any] | None:
    """Two-point CPU sample of all ``msedge.exe`` processes plus RAM and GPU adapters.

    Returns:
        Raw sample dict (``processes``, ``free_mb``, ``total_mb``, ``gpus``) or ``None``
        when not on Windows or PowerShell fails.
    """
    if platform.system() != "Windows":
        return None
    script = _PS_TEMPLATE.replace("__MS__", str(int(sample_seconds * 1000)))
    run_fn = run or subprocess.run
    try:
        completed = run_fn(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=sample_seconds + 30,
            check=False,
        )
        data = json.loads(completed.stdout or "")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    procs = data.get("processes")
    data["processes"] = procs if isinstance(procs, list) else ([procs] if procs else [])
    gpus = data.get("gpus")
    data["gpus"] = gpus if isinstance(gpus, list) else ([gpus] if gpus else [])
    return data


def blocked_extension_ids(policy_value: str | None) -> set[str]:
    """IDs with ``installation_mode: blocked`` in an ExtensionSettings JSON value."""
    try:
        body = json.loads(policy_value or "")
    except json.JSONDecodeError:
        return set()
    if not isinstance(body, dict):
        return set()
    return {
        ext_id
        for ext_id, cfg in body.items()
        if isinstance(cfg, dict) and cfg.get("installation_mode") == "blocked"
    }


def _parse_utc(stamp: Any) -> datetime | None:
    try:
        return datetime.strptime(str(stamp), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _is_live_fix(row: dict[str, Any]) -> bool:
    if row.get("dry_run") is not False:
        return False
    event = row.get("event")
    if event == "browser_blank_screen_fix":
        return row.get("action_allowed") is True
    if event in ("edge_extensions_disable", "edge_extensions_restore"):
        return row.get("mutated") is True
    return False


def last_live_edge_fix(audit_root: Path | None = None) -> dict[str, Any] | None:
    """Most recent live Edge mutation recorded by the toolkit (cache clear or policy)."""
    root = audit_root or audit_dir()
    latest: tuple[datetime, dict[str, Any]] | None = None
    for name in ("browser-blank-screen.jsonl", "edge-extensions-policy.jsonl"):
        try:
            lines = (root / name).read_text(encoding="utf-8").splitlines()[-_AUDIT_TAIL_LINES:]
        except OSError:
            continue
        for line in lines:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or not _is_live_fix(row):
                continue
            when = _parse_utc(row.get("timestamp_utc"))
            if when and (latest is None or when > latest[0]):
                latest = (when, {"event": row["event"], "timestamp_utc": row["timestamp_utc"]})
    return latest[1] if latest else None


def _capable_gpu(gpus: list[Any]) -> str | None:
    for name in gpus:
        if any(marker in str(name).lower() for marker in _CAPABLE_GPU_MARKERS):
            return str(name)
    return None


def analyze_edge_runtime(
    sample: dict[str, Any] | None,
    *,
    sample_seconds: float = DEFAULT_SAMPLE_SECONDS,
    last_fix: dict[str, Any] | None = None,
    hw_accel_enabled: bool | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Turn a raw process sample into a summary plus severity-ordered ``issues[]``."""
    if not sample:
        return {"sampled": False, "issues": [], "limitations": list(RUNTIME_LIMITATIONS)}

    procs = [p for p in sample.get("processes") or [] if isinstance(p, dict)]
    window = max(sample_seconds, 0.1)
    browser = next((p for p in procs if p.get("type") == "browser"), None)
    started = _parse_utc(browser.get("start_utc")) if browser else None
    total_edge_mb = sum(int(p.get("mb") or 0) for p in procs)
    free_mb = int(sample.get("free_mb") or 0)
    total_mb = int(sample.get("total_mb") or 0)
    issues: list[dict[str, Any]] = []

    busy = sorted(
        (
            {
                "pid": p.get("pid"),
                "extension": bool(p.get("extension")),
                "cpu_percent_of_core": round(100 * float(p.get("cpu_seconds") or 0) / window),
                "mb": p.get("mb"),
            }
            for p in procs
            if p.get("type") == "renderer"
            and float(p.get("cpu_seconds") or 0) / window >= HUNG_CORE_FRACTION
        ),
        key=lambda r: -r["cpu_percent_of_core"],
    )
    tabs = [b for b in busy if not b["extension"]]
    exts = [b for b in busy if b["extension"]]
    if tabs:
        pct = ", ".join(f"{b['cpu_percent_of_core']}%" for b in tabs)
        issues.append(
            {
                "id": "tab_frozen",
                "severity": "high",
                "summary": (
                    f"{len(tabs)} Edge tab process(es) are pegging the CPU ({pct} of a core) — "
                    "the usual cause of 'This page isn't responding'."
                ),
                "evidence": tabs,
                "user_action": (
                    "Click 'Exit page' on the frozen tab, or press Shift+Esc in Edge, select "
                    "the tab with the highest CPU, and click End process; then reload it once."
                ),
            }
        )
    if exts:
        issues.append(
            {
                "id": "extension_busy",
                "severity": "medium",
                "summary": f"{len(exts)} Edge extension process(es) are using a full CPU core.",
                "evidence": exts,
                "user_action": (
                    "Press Shift+Esc in Edge to see which extension is busy; disable it on "
                    "edge://extensions or use the extension-block rung."
                ),
            }
        )

    fix_time = _parse_utc((last_fix or {}).get("timestamp_utc"))
    if started and fix_time and started < fix_time:
        issues.append(
            {
                "id": "restart_pending",
                "severity": "medium",
                "summary": (
                    f"Edge has not been restarted since the last fix ({last_fix['event']} at "
                    f"{last_fix['timestamp_utc']}), so it may not be fully active."
                ),
                "evidence": {"edge_started_utc": browser.get("start_utc"), "last_fix": last_fix},
                "user_action": "Close Edge completely (... > Close Microsoft Edge) and reopen it.",
            }
        )

    if total_mb and free_mb < max(LOW_FREE_RAM_MB, LOW_FREE_RAM_FRACTION * total_mb):
        issues.append(
            {
                "id": "memory_pressure",
                "severity": "medium",
                "summary": (
                    f"Only {free_mb / 1024:.1f} GB of {total_mb / 1024:.0f} GB RAM is free; Edge "
                    f"uses {total_edge_mb / 1024:.1f} GB across {len(procs)} processes."
                ),
                "evidence": {"free_mb": free_mb, "edge_mb": total_edge_mb, "processes": len(procs)},
                "user_action": "Close unused tabs and other heavy apps, then restart Edge.",
            }
        )

    gpu_flag_off = any(
        p.get("gpu_disabled_flag") for p in procs if p.get("type") in ("gpu-process", "browser")
    )
    capable = _capable_gpu(sample.get("gpus") or [])
    if capable and (gpu_flag_off or hw_accel_enabled is False):
        issues.append(
            {
                "id": "gpu_acceleration_off",
                "severity": "medium",
                "summary": (
                    f"Edge is rendering without the GPU even though a capable GPU is present "
                    f"({capable}); heavy pages then run on the CPU."
                ),
                "evidence": {"gpu_disabled_flag": gpu_flag_off, "setting": hw_accel_enabled},
                "user_action": (
                    "Edge Settings > System and performance > turn on 'Use graphics "
                    "acceleration when available' > Restart."
                ),
            }
        )

    issues.sort(key=lambda i: _SEVERITY_ORDER.get(i["severity"], 9))
    uptime = (
        round(((now or datetime.now(UTC)) - started).total_seconds() / 3600, 1) if started else None
    )
    return {
        "sampled": True,
        "sample_seconds": sample_seconds,
        "edge_running": bool(procs),
        "edge_uptime_hours": uptime,
        "edge_process_count": len(procs),
        "edge_memory_mb": total_edge_mb,
        "free_ram_mb": free_mb,
        "total_ram_mb": total_mb,
        "gpu_adapters": sample.get("gpus") or [],
        "gpu_disabled_flag": gpu_flag_off,
        "issues": issues,
        "limitations": list(RUNTIME_LIMITATIONS),
    }
