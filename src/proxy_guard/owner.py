"""Correlate localhost proxy ports to listening PIDs using netstat/tasklist/CIM probes.

Pipeline position:
    ``observability.snapshot`` (indirect), ``command_handlers.proxy-owner/monitor``.

Key invariants:
    Never modifies registry or firewall rules.
    Sets ``permission_limited`` when WMI JSON or command-line fields are unavailable.

Audit Notes:
    Evidence quality depends on privilege level; correlate with ``proxy-status`` snapshots.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from typing import Any

from ..attribution.port_owner import netstat_listen_rows, owners_for_port, parse_tasklist_csv_data
from ..core.models import PortOwnerRecord
from ..diagnostics.collector import run_command
from ..observability.tcp_table import capture_netstat_ano


def _full_tasklist_text(run: Callable[..., Any]) -> tuple[int, str]:
    cmd = ["tasklist", "/FO", "CSV", "/NH"]
    try:
        proc = run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _cim_process_json(pid: int) -> tuple[dict[str, Any] | None, bool]:
    ps = (
        f"$e=$null; try {{"
        f"$p=Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" -ErrorAction Stop; "
        f"$e=[pscustomobject]@{{"
        f"CommandLine=$p.CommandLine;ParentProcessId=$p.ParentProcessId;"
        f"ExecutablePath=$p.ExecutablePath;Caption=$p.Name}}}} catch {{ $e=$null }}; "
        f"$e | ConvertTo-Json -Compress"
    )
    code, out = run_command(["powershell", "-NoProfile", "-Command", ps], timeout=25.0)
    if code != 0 or not out.strip():
        return None, True
    try:
        data = json.loads(out.strip())
        if isinstance(data, dict):
            return data, False
    except json.JSONDecodeError:
        return None, True
    return None, True


def _parent_name(parent_pid: int | None, task_map: dict[int, str]) -> str | None:
    if parent_pid is None:
        return None
    return task_map.get(parent_pid)


def resolve_localhost_proxy_owners(
    port: int | None,
    *,
    run: Callable[..., Any] = subprocess.run,
) -> tuple[tuple[PortOwnerRecord, ...], tuple[str, ...]]:
    """Resolve listening PIDs for ``port`` and enrich with tasklist + optional CIM data.

    Returns:
        Tuple of owner records and permission/skip notes.
    """
    notes: list[str] = []
    if port is None:
        return (), ("No localhost proxy port parsed; skipped owner lookup.",)

    code, nst = capture_netstat_ano(run=run)
    if code != 0:
        notes.append(f"netstat failed (code {code}); owner list may be empty.")
    rows = netstat_listen_rows(nst)
    pids = owners_for_port(rows, port)
    if not pids:
        notes.append(f"No LISTENING rows found for port {port} in netstat snapshot.")

    tcode, task_out = _full_tasklist_text(run)
    task_map: dict[int, str] = {}
    if tcode == 0:
        task_map = parse_tasklist_csv_data(task_out)
    else:
        notes.append("tasklist failed; process names may be unknown.")

    owners: list[PortOwnerRecord] = []
    for pid in pids:
        name = task_map.get(pid)
        cim, lim = _cim_process_json(pid)
        cmdline = None
        exepath = None
        parent_pid = None
        if isinstance(cim, dict):
            cmdline = cim.get("CommandLine")
            exepath = cim.get("ExecutablePath")
            parent_pid = cim.get("ParentProcessId")
            if isinstance(parent_pid, str) and parent_pid.isdigit():
                parent_pid = int(parent_pid)
        parent_name = _parent_name(parent_pid, task_map)
        owners.append(
            PortOwnerRecord(
                port=port,
                pid=pid,
                process_name=name,
                state="Listen",
                local_address=None,
                parent_pid=int(parent_pid) if isinstance(parent_pid, int) else None,
                parent_name=parent_name,
                command_line=cmdline if isinstance(cmdline, str) else None,
                executable_path=exepath if isinstance(exepath, str) else None,
                permission_limited=lim or cmdline is None,
            ),
        )

    return tuple(owners), tuple(notes)


def attribution_payload(
    port: int | None,
    *,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Return JSON-serializable dict keyed by ``port``, ``owners``, and ``notes``."""
    owners, notes = resolve_localhost_proxy_owners(port, run=run)
    block: dict[str, Any] = {"port": port, "owners": []}
    for o in owners:
        entry = {"port": o.port, **o.to_dict()}
        block["owners"].append(entry)
    block["notes"] = list(notes)
    return block
