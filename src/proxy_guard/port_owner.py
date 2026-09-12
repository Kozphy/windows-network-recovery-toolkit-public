"""Localhost proxy port ownership proof (read-only).

Resolves which process listens on ``127.0.0.1:<port>`` when ProxyServer points at loopback.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .owner import resolve_localhost_proxy_owners


def _resolve_via_psutil(port: int) -> PortOwnerEvidence | None:
    try:
        import psutil  # type: ignore[import-untyped]
    except ImportError:
        return None
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr and conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
            pid = conn.pid
            if pid is None:
                continue
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                cmdline = " ".join(proc.cmdline())
                exe = proc.exe()
            except (psutil.Error, OSError):
                name, cmdline, exe = "", "", ""
            parent_name = ""
            try:
                ppid = proc.ppid()
                parent_name = psutil.Process(ppid).name()
            except (psutil.Error, OSError, UnboundLocalError):
                parent_name = ""
            return PortOwnerEvidence(
                port=port,
                process_id=pid,
                process_name=name,
                executable_path=exe,
                command_line=cmdline,
                parent_process=parent_name,
                connection_state="Listen",
                local_address="127.0.0.1",
                local_port=port,
                confidence=0.7,
                proof_level="CORRELATED",
                notes=["resolved_via_psutil"],
            )
    return None


def _resolve_via_net_tcp_connection(port: int, run: Callable[..., Any]) -> PortOwnerEvidence | None:
    ps = (
        f"$c=Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | "
        f"Select-Object -First 1; if($c){{$p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; "
        f"[pscustomobject]@{{Pid=$c.OwningProcess;Name=$p.ProcessName;Path=$p.Path;"
        f"Parent=(Get-CimInstance Win32_Process -Filter \"ProcessId=$($c.OwningProcess)\").ParentProcessId}}}} "
        f"| ConvertTo-Json -Compress"
    )
    try:
        proc = run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    pid = data.get("Pid")
    return PortOwnerEvidence(
        port=port,
        process_id=int(pid) if pid is not None else None,
        process_name=str(data.get("Name") or ""),
        executable_path=str(data.get("Path") or ""),
        command_line="",
        parent_process=str(data.get("Parent") or ""),
        connection_state="Listen",
        local_address="127.0.0.1",
        local_port=port,
        confidence=0.78,
        proof_level="CORRELATED",
        notes=["resolved_via_get_net_tcp_connection"],
    )


@dataclass
class PortOwnerEvidence:
    """Process that owns the localhost proxy listener port."""

    port: int
    process_id: int | None
    process_name: str
    executable_path: str
    command_line: str
    parent_process: str
    connection_state: str
    local_address: str
    local_port: int
    confidence: float
    proof_level: str = "CORRELATED"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "port": self.port,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "executable_path": self.executable_path,
            "command_line": self.command_line,
            "parent_process": self.parent_process,
            "connection_state": self.connection_state,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "confidence": self.confidence,
            "proof_level": self.proof_level,
            "notes": list(self.notes),
        }


def _from_fixture(path: Path) -> PortOwnerEvidence | None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "port_owner" in data:
        data = data["port_owner"]
    if not isinstance(data, dict):
        return None
    port = int(data.get("port") or data.get("local_port") or 0)
    return PortOwnerEvidence(
        port=port,
        process_id=data.get("process_id") or data.get("pid"),
        process_name=str(data.get("process_name") or data.get("name") or ""),
        executable_path=str(data.get("executable_path") or data.get("exe") or ""),
        command_line=str(data.get("command_line") or ""),
        parent_process=str(data.get("parent_process") or data.get("parent_name") or ""),
        connection_state=str(data.get("connection_state") or "Listen"),
        local_address=str(data.get("local_address") or "127.0.0.1"),
        local_port=int(data.get("local_port") or port),
        confidence=float(data.get("confidence") or 0.7),
        proof_level=str(data.get("proof_level") or "CORRELATED"),
        notes=list(data.get("notes") or []),
    )


def resolve_port_owner(
    port: int | None,
    *,
    run: Callable[..., Any] = subprocess.run,
    fixture_path: Path | None = None,
) -> PortOwnerEvidence | None:
    """Resolve localhost listener owner for a proxy port.

    Args:
        port: Numeric localhost port from ProxyServer.
        run: Injectable subprocess runner.
        fixture_path: Fixture JSON with ``port_owner`` object for CI.

    Returns:
        Port owner evidence or None when port is missing or unresolved.
    """
    if fixture_path is not None and fixture_path.is_file():
        row = _from_fixture(fixture_path)
        if row is not None:
            return row
    if port is None:
        return None
    ps_row = _resolve_via_net_tcp_connection(port, run)
    if ps_row is not None:
        return ps_row
    psutil_row = _resolve_via_psutil(port)
    if psutil_row is not None:
        return psutil_row
    owners, notes = resolve_localhost_proxy_owners(port, run=run)
    if not owners:
        return None
    primary = owners[0]
    return PortOwnerEvidence(
        port=port,
        process_id=primary.pid,
        process_name=primary.process_name,
        executable_path=primary.executable_path or "",
        command_line=primary.command_line or "",
        parent_process=primary.parent_name or "",
        connection_state="Listen",
        local_address="127.0.0.1",
        local_port=port,
        confidence=0.75 if not primary.permission_limited else 0.55,
        proof_level="CORRELATED",
        notes=list(notes),
    )
