"""Enrich process inventory rows with SHA256, parent metadata, and listening ports."""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable
from typing import Any

from ..core.time_utils import utc_now_iso
from ..observability.tcp_table import capture_netstat_ano
from .investigation_models import ProcessSnapshotRecord
from .process_inventory import capture_process_inventory


def _sha256_file(path: str) -> str | None:
    try:
        p = path.strip().strip('"')
        if not p:
            return None
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _listening_ports_by_pid(run: Callable[..., Any]) -> dict[int, set[int]]:
    code, text = capture_netstat_ano(run=run)
    if code != 0 or not text.strip():
        return {}
    out: dict[int, set[int]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if parts[3].upper() != "LISTENING":
            continue
        local = parts[1]
        pid_s = parts[-1]
        if not pid_s.isdigit():
            continue
        pid = int(pid_s)
        port_part = local.rsplit(":", 1)[-1]
        if not port_part.isdigit():
            continue
        out.setdefault(pid, set()).add(int(port_part))
    return out


def _enrich_rows(
    rows: list[dict[str, Any]],
    *,
    listen_map: dict[int, set[int]],
    matched_port: int | None,
) -> list[ProcessSnapshotRecord]:
    by_pid = {int(r["pid"]): r for r in rows if isinstance(r.get("pid"), int)}
    enriched: list[ProcessSnapshotRecord] = []
    for row in rows:
        pid = row.get("pid")
        if not isinstance(pid, int):
            continue
        exe = row.get("executable_path")
        exe_s = str(exe).strip() if isinstance(exe, str) and exe.strip() else None
        path_status: str = "resolved" if exe_s else "unresolved_path"
        sha = _sha256_file(exe_s) if exe_s else None
        ppid = row.get("parent_pid")
        parent = by_pid.get(int(ppid)) if isinstance(ppid, int) else None
        ports = tuple(sorted(listen_map.get(pid, set())))
        enriched.append(
            ProcessSnapshotRecord(
                pid=pid,
                process_name=str(row.get("process_name") or "").strip() or None,
                executable_path=exe_s,
                command_line=str(row.get("command_line") or "").strip() or None,
                parent_pid=int(ppid) if isinstance(ppid, int) else None,
                parent_process_name=(
                    str(parent.get("process_name")).strip()
                    if parent and parent.get("process_name")
                    else None
                ),
                parent_command_line=(
                    str(parent.get("command_line")).strip()
                    if parent and parent.get("command_line")
                    else None
                ),
                creation_time_utc=str(row.get("creation_time_utc") or "").strip() or None,
                sha256=sha,
                path_status=path_status,  # type: ignore[arg-type]
                listening_tcp_ports=ports,
                matched_localhost_port=matched_port if matched_port in ports else None,
            ),
        )
    return enriched


def capture_enriched_process_snapshot(
    *,
    proxy_localhost_port: int | None,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Capture inventory plus enriched :class:`ProcessSnapshotRecord` rows."""
    inventory = capture_process_inventory(proxy_localhost_port=proxy_localhost_port, run=run)
    listen_map = _listening_ports_by_pid(run)
    rows = list(inventory.get("process_rows") or [])
    enriched = _enrich_rows(rows, listen_map=listen_map, matched_port=proxy_localhost_port)
    primary = enriched[0] if enriched else None
    return {
        "timestamp_utc": utc_now_iso(),
        "proxy_localhost_port": proxy_localhost_port,
        "process_rows": [r.to_jsonable() for r in enriched],
        "primary_snapshot": primary.to_jsonable() if primary else None,
        "listening_pids": inventory.get("listening_pids") or [],
        "localhost_listener_block": inventory.get("localhost_listener_block") or {},
        "collection_warnings": inventory.get("collection_warnings") or [],
    }


def snapshot_record_from_owner(
    owner: dict[str, Any] | None,
    *,
    process_rows: list[dict[str, Any]] | None = None,
    matched_port: int | None = None,
) -> ProcessSnapshotRecord | None:
    """Build a snapshot record from port owner dict plus optional inventory rows."""
    if not owner or owner.get("pid") is None:
        return None
    pid = int(owner["pid"])
    rows = process_rows or []
    by_pid = {int(r["pid"]): r for r in rows if isinstance(r.get("pid"), int)}
    row = by_pid.get(pid, owner)
    exe = row.get("executable_path") or owner.get("executable_path")
    exe_s = str(exe).strip() if isinstance(exe, str) and exe.strip() else None
    ppid = row.get("parent_pid") if row.get("parent_pid") is not None else owner.get("parent_pid")
    parent = by_pid.get(int(ppid)) if isinstance(ppid, int) else None
    return ProcessSnapshotRecord(
        pid=pid,
        process_name=str(row.get("process_name") or owner.get("process_name") or "").strip() or None,
        executable_path=exe_s,
        command_line=str(row.get("command_line") or owner.get("command_line") or "").strip() or None,
        parent_pid=int(ppid) if isinstance(ppid, int) else None,
        parent_process_name=str(
            parent.get("process_name") if parent else owner.get("parent_name") or ""
        ).strip()
        or None,
        parent_command_line=str(parent.get("command_line") or "").strip() if parent else None,
        creation_time_utc=str(row.get("creation_time_utc") or owner.get("start_time") or "").strip()
        or None,
        sha256=_sha256_file(exe_s) if exe_s else None,
        path_status="resolved" if exe_s else "unresolved_path",  # type: ignore[arg-type]
        listening_tcp_ports=(matched_port,) if matched_port else (),
        matched_localhost_port=matched_port if owner.get("listener_on_proxy_port") else None,
    )
