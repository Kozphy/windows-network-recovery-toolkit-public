"""Heuristic attribution combining listen-port snapshots with optional Sysmon verification."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .eventlog_attribution import attribution_from_windows_event_logs
from .models import AttributionResult, ProcessIdentity


def _try_psutil_enrich(pid: int | None) -> tuple[
    str | None,
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
    tuple[str, ...],
]:
    limits: tuple[str, ...] = ()
    if pid is None:
        return None, None, None, None, None, None, limits
    try:
        import psutil  # type: ignore[import-not-found]
        from psutil import Error as PsutilError  # noqa: N811
        from psutil import NoSuchProcess  # noqa: N811
    except ImportError:
        return None, None, None, None, None, None, ("psutil_not_installed_optional_dependency",)

    try:
        proc = psutil.Process(int(pid))
    except (NoSuchProcess, PsutilError, OSError, ValueError):
        return None, None, None, None, None, None, ("psutil_process_not_found_or_invalid_pid",)
    exe_s = None
    try:
        exe_s = proc.exe()
    except (PsutilError, OSError):
        limits += ("executable_path_optional_lookup_failed_or_denied",)
    cmdline_str = None
    try:
        cmdline_str = subprocess.list2cmdline(proc.cmdline())
    except (PsutilError, ValueError, OSError):
        limits += ("cmdline_optional_lookup_failed",)
    utc = None
    try:
        create = proc.create_time()
        utc = datetime.fromtimestamp(create, tz=UTC).isoformat().replace("+00:00", "Z")
    except (PsutilError, OSError, OverflowError):
        limits += ("create_time_optional_lookup_failed",)

    ppid_val: int | None = None
    parent_exe_s: str | None = None
    uname = None
    try:
        uname = proc.username()
    except (PsutilError, NotImplementedError):
        limits += ("username_optional_lookup_failed",)
    try:
        parent = proc.parent()
        ppid_candidate = getattr(parent, "pid", None)
        if isinstance(ppid_candidate, int):
            ppid_val = ppid_candidate
        parent_exe_s = parent.exe()
    except (PsutilError, OSError):
        limits += ("parent_process_optional_lookup_failed_or_denied",)

    return str(exe_s) if exe_s else None, cmdline_str, utc, ppid_val, parent_exe_s, uname if isinstance(uname, str) else None, limits


def _best_effort_from_owner_row(row: dict[str, Any]) -> AttributionResult:
    pid = row.get("pid")
    pid_i = int(pid) if isinstance(pid, int) else None
    if pid_i is None and isinstance(pid, str) and pid.isdigit():
        pid_i = int(pid)
    name = row.get("process_name")
    exe_known = row.get("executable_path")
    cmd_known = row.get("command_line")
    parent_pid = row.get("parent_pid")
    pid_parent = None
    if isinstance(parent_pid, int):
        pid_parent = parent_pid
    elif isinstance(parent_pid, str) and parent_pid.isdigit():
        pid_parent = int(parent_pid)

    ps_exe, ps_cmd, ps_time, ppid_extra, parent_exe_extra, username, limits = _try_psutil_enrich(pid_i)
    exe = ps_exe if ps_exe else (str(exe_known) if isinstance(exe_known, str) else None)
    cmdline = ps_cmd if ps_cmd else (str(cmd_known) if isinstance(cmd_known, str) else None)
    ppid = ppid_extra if isinstance(ppid_extra, int) else pid_parent

    confidence: str = "low"
    if exe:
        confidence = "medium"
    evidence = ("listen_owner_row_plus_optional_psutil",)
    process = ProcessIdentity(
        pid=pid_i,
        ppid=ppid if isinstance(ppid, int) else None,
        exe=exe.strip('"') if isinstance(exe, str) else None,
        name=name if isinstance(name, str) else None,
        cmdline=cmdline,
        create_time_utc=ps_time,
        user=username,
        source="best_effort_listen_owner",
    )
    limitation_core = ("polling_based_attribution_not_registry_writer_proof",)
    return AttributionResult(
        mode="best_effort_process_snapshot",
        confidence=confidence,  # type: ignore[arg-type]
        process=process,
        evidence=evidence,
        limitations=limitation_core + limits,
    )


def build_best_effort_attribution_from_payload(owners_payload: dict[str, Any]) -> AttributionResult:
    """Build best effort attribution from payload.
    
    Args:
        owners_payload: The owners payload value supplied by the caller.
    
    Returns:
        The AttributionResult result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    rows = owners_payload.get("owners") or []
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return _best_effort_from_owner_row(rows[0])
    return AttributionResult(
        mode="unknown",
        confidence="unknown",
        process=None,
        evidence=("no_listen_owner_rows_correlated",),
        limitations=("cannot_resolve_process_without_listen_port_snapshot",),
    )


def resolve_attribution(
    *,
    mode: str,
    owners_payload: dict[str, Any],
    run: Callable[..., Any],
) -> AttributionResult:
    """Prefer Sysmon (*auto*/*eventlog* modes); degrade to correlate listen owners."""

    m = mode.strip().lower()
    if m in {"auto", "eventlog"}:
        ev_res = attribution_from_windows_event_logs(run=run, mode=m)
        if ev_res is not None:
            return ev_res

    best = build_best_effort_attribution_from_payload(owners_payload)
    if m == "eventlog":
        extra = (*best.limitations, "eventlog_mode_without_matching_sysmon_record")
        return AttributionResult(
            mode="best_effort_process_snapshot",
            confidence=best.confidence,
            process=best.process,
            evidence=best.evidence + ("fallback_from_eventlog_preflight",),
            limitations=extra,
        )
    return best
