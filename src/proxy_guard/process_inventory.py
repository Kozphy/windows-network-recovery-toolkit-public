"""Collect capped process snapshots and localhost listener correlations for proxy drift attribution.

Module responsibility:
    After :mod:`~src.proxy_guard.state` reports a localhost ``ProxyServer`` port, gathers Win32 process
    metadata (PID, parent, exe path, command line, creation time when available) and merges listener-derived
    owner stubs from :func:`~src.proxy_guard.owner.attribution_payload`.

System placement:
    Primary consumer is :func:`~src.proxy_guard.proxy_watch.run_proxy_watch_loop` (``proxy-watch`` CLI);
    unit tests inject ``run`` to simulate probe failure.

Key invariants:
    * Subprocess launches use argv lists with ``shell=False``; no interactive PowerShell profiles.

Side effects:
    * Spawns ``powershell.exe`` for CIM JSON export and invokes listener attribution (typically netstat-derived
      parsing in sibling module).

Failure modes:
    * Returns empty ``process_rows`` with informative ``collection_warnings``/``notes`` amalgamation when
      CIM serialization fails—callers treat partial evidence as acceptable.

Audit Notes:
    * Inventory reflects **moment-in-time** process tables; ephemeral writers may terminate before polling.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from typing import Any

from .attribution_model import ProxyActor
from .owner import attribution_payload

_HEURISTIC_LEXICON = frozenset(
    {
        "cursor",
        "code",
        "claude",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "python",
        "pip",
        "git",
        "clash",
        "v2ray",
        "sing-box",
        "singbox",
        "shadowsocks",
        "vpn",
        "proxy",
        "updater",
        "electron",
    },
)


def _run_powershell_json(expression: str, *, run: Callable[..., Any], timeout: float = 45.0) -> Any:
    """Execute a PowerShell ``-Command`` snippet and deserialize JSON stdout.

    Args:
        expression: Inline script producing JSON text on success.
        run: ``subprocess.run`` compliant callable used by tests/production.
        timeout: Upper bound seconds for frozen-hang protection.

    Returns:
        Parsed JSON (``list`` | ``dict``) or ``None`` on non-zero exit / empty stdout / decode failure /
        ``OSError`` / :class:`subprocess.TimeoutExpired`.

    Side effects:
        Launches ``powershell.exe`` with ``-NoProfile -NonInteractive``.

    Raises:
        None—all failures surface as ``None``.
    """
    argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", expression]
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    text = (proc.stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def capture_process_inventory(
    *,
    proxy_localhost_port: int | None,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Snapshot capped process metadata plus localhost listener attribution for drift correlation.

    Args:
        proxy_localhost_port: TCP port inferred from localhost ``ProxyServer`` (``None`` disables targeted
            listener lookups but still gathers process rows).
        run: Injectable ``subprocess.run`` surrogate for deterministic tests.

    Returns:
        Dict containing:
            * ``process_rows``: Normalized rows (possibly empty) with PID/PPID/name/exe/command line/ctime.
            * ``localhost_listener_block``: Raw attribution payload merged from :func:`~src.proxy_guard.owner.attribution_payload`.
            * ``listening_pids``: Sorted unique PIDs implicated by listener owners.
            * ``collection_warnings``: Merge of local warnings plus listener ``notes``.

    Side effects:
        Spawns subprocesses per ``proxy_localhost_port`` listener logic and capped CIM export.

    Idempotency:
        Read-only sampling—multiple calls duplicate work but **do not** mutate machine state via this helper.

    Data shape assumptions:
        Creation timestamps may arrive as WMI datetime strings or ISO fragments; normalization stores string
        forms best-effort for downstream lexical scoring only.

    Engineering Notes:
        When listeners are known, reorder places listener chains ahead of alphabetical noise to keep parent
        resolution paths near candidate PIDs inside :mod:`~src.proxy_guard.change_attribution`.
    """

    warnings: list[str] = []

    listen_block = attribution_payload(proxy_localhost_port, run=run)
    owners = listen_block.get("owners") or []
    listen_pids: set[int] = set()
    for o in owners:
        if isinstance(o, dict) and isinstance(o.get("pid"), int):
            listen_pids.add(int(o["pid"]))

    ps_expr = (
        '& { $ErrorActionPreference="SilentlyContinue"; '
        'Get-CimInstance Win32_Process | Select-Object -First 520 '
        'ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate '
        '| ConvertTo-Json -Depth 8 -Compress }'
    )

    raw_rows = _run_powershell_json(ps_expr, run=run)
    if raw_rows is None:
        warnings.append("cim_snapshot_unavailable")

    normalized: list[dict[str, Any]] = []
    iterable: list[Any]
    if isinstance(raw_rows, list):
        iterable = list(raw_rows)
    elif isinstance(raw_rows, dict):
        iterable = [raw_rows]
    else:
        iterable = []

    for row in iterable:
        if not isinstance(row, dict):
            continue
        try:
            pid = row.get("pid") if "pid" in row else row.get("ProcessId")
            pp_raw = row.get("parent_pid") if "parent_pid" in row else row.get("ParentProcessId")
            ppid = None
            if isinstance(pp_raw, int):
                ppid = pp_raw
            elif isinstance(pp_raw, str) and pp_raw.strip().isdigit():
                ppid = int(pp_raw.strip())
            ctime_raw = row.get("CreationDate")
            ct_s: str | None
            if ctime_raw is None:
                ct_s = row.get("creation_time_utc")
            elif isinstance(ctime_raw, str):
                ct_s = ctime_raw
            elif hasattr(ctime_raw, "strftime"):
                try:
                    ct_s = ctime_raw.isoformat()
                except (OSError, ValueError):
                    ct_s = str(ctime_raw)
            else:
                ct_s = str(ctime_raw) if ctime_raw is not None else None

            normalized.append(
                {
                    "pid": int(pid) if pid is not None else None,
                    "parent_pid": ppid,
                    "process_name": row.get("Name") or row.get("process_name"),
                    "executable_path": row.get("ExecutablePath") or row.get("executable_path"),
                    "command_line": row.get("CommandLine") or row.get("command_line"),
                    "creation_time_utc": ct_s,
                },
            )
        except (TypeError, ValueError):
            continue

    if listen_pids and normalized:
        by_pid = {r["pid"]: r for r in normalized if isinstance(r.get("pid"), int)}
        ordered: list[dict[str, Any]] = []
        seen: set[int] = set()

        def add_chain(pid: int | None) -> None:
            if pid is None or pid <= 4 or pid in seen:
                return
            seen.add(pid)
            row = by_pid.get(pid)
            if row:
                ordered.append(row)
                ppid = row.get("parent_pid")
                if isinstance(ppid, int):
                    add_chain(ppid)

        for lp in sorted(list(listen_pids)):
            add_chain(lp)
        for r in normalized:
            pid = r.get("pid")
            if isinstance(pid, int) and pid not in seen:
                ordered.append(r)
        normalized = ordered

    return {
        "process_rows": normalized,
        "localhost_listener_block": listen_block,
        "collection_warnings": warnings + list(listen_block.get("notes") or []),
        "listening_pids": sorted(list(listen_pids)),
    }


def collect_recent_process_inventory(*, limit: int = 30, run: Callable[..., Any] = subprocess.run) -> list[ProxyActor]:
    """Return newest ``Win32_Process`` rows mapped to :class:`~src.proxy_guard.attribution_model.ProxyActor`.

    Rows sort by WMI ``CreationDate`` descending server-side via PowerShell ``Sort-Object`` (best-effort).

    Raises:
        None — returns an empty list on probe failure.
    """
    cap = max(1, min(int(limit), 520))
    ps_expr = (
        '& { $ErrorActionPreference="SilentlyContinue"; '
        "Get-CimInstance Win32_Process | Sort-Object {[datetime]$_.CreationDate} -Descending "
        f"| Select-Object -First {cap} "
        'ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate '
        "| ConvertTo-Json -Depth 8 -Compress }"
    )

    raw_rows = _run_powershell_json(ps_expr, run=run)
    iterable: list[Any]
    if isinstance(raw_rows, list):
        iterable = list(raw_rows)
    elif isinstance(raw_rows, dict):
        iterable = [raw_rows]
    else:
        return []

    out: list[ProxyActor] = []
    for row in iterable:
        if not isinstance(row, dict):
            continue
        try:
            pid_raw = row.get("ProcessId") if "ProcessId" in row else row.get("pid")
            pp_raw = row.get("ParentProcessId") if "ParentProcessId" in row else row.get("parent_pid")
            pid: int | None = None
            if isinstance(pid_raw, int):
                pid = pid_raw
            elif isinstance(pid_raw, str) and pid_raw.strip().isdigit():
                pid = int(pid_raw.strip())
            if pid is None:
                continue
            ppid: int | None = None
            if isinstance(pp_raw, int):
                ppid = pp_raw
            elif isinstance(pp_raw, str) and pp_raw.strip().isdigit():
                ppid = int(pp_raw.strip())
            name = row.get("Name") or row.get("process_name")
            exe = row.get("ExecutablePath") or row.get("executable_path")
            cmd = row.get("CommandLine") or row.get("command_line")
            ctime_raw = row.get("CreationDate")
            ct_s: str | None = None
            if isinstance(ctime_raw, str):
                ct_s = ctime_raw
            elif hasattr(ctime_raw, "isoformat"):
                try:
                    ct_s = ctime_raw.isoformat()
                except (OSError, ValueError):
                    ct_s = str(ctime_raw)
            elif ctime_raw is not None:
                ct_s = str(ctime_raw)
            out.append(
                ProxyActor(
                    pid=pid,
                    parent_pid=ppid,
                    process_name=str(name).strip() if isinstance(name, str) else None,
                    image_path=str(exe).strip() if isinstance(exe, str) and exe.strip() else None,
                    command_line=str(cmd).strip() if isinstance(cmd, str) and cmd.strip() else None,
                    started_at=ct_s,
                ),
            )
        except (TypeError, ValueError):
            continue

    return out


def heuristic_proxy_actor_candidates(inventory: list[ProxyActor]) -> list[ProxyActor]:
    """Prefer processes whose textual metadata matches developer/proxy tool substrings."""

    matched: list[ProxyActor] = []
    for a in inventory:
        hay = " ".join(
            x
            for x in (
                a.process_name or "",
                (a.image_path or ""),
                (a.command_line or ""),
            )
            if x
        ).lower()
        if any(tok in hay for tok in _HEURISTIC_LEXICON):
            matched.append(a)
    return matched
