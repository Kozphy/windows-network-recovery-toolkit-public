"""Process snapshot for dashboard Process view (soft-fail on access denied).

Module responsibility:
    Collect PID metadata and TCP endpoints for related processes shown in the UI.
    Soft-fail per field / per PID so one Access Denied does not blank the page.

System placement:
    Invoked by NiceGUI views on refresh; optional ``inject`` for tests.

Key invariants:
    * Does not kill, suspend, or modify processes.
    * Missing ``psutil`` returns an empty payload with limitations, not an exception.

Side effects:
    * Read-only ``psutil`` process queries when not using ``inject``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ProcessSnapshotRow:
    """One process row for the dashboard Process Snapshot table.

    Attributes:
        access_denied_fields: Field names that could not be read due to permissions.
        errors: Soft-fail messages; row may still be partially populated.
    """

    pid: int | None
    ppid: int | None
    name: str | None
    executable: str | None
    command_line: str | None
    username: str | None
    tcp_endpoints: list[str] = field(default_factory=list)
    access_denied_fields: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the row to a plain dict safe for JSON output."""
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "executable": self.executable,
            "command_line": self.command_line,
            "username": self.username,
            "tcp_endpoints": list(self.tcp_endpoints),
            "access_denied_fields": list(self.access_denied_fields),
            "errors": list(self.errors),
        }


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_process_snapshot(
    pids: list[int],
    *,
    inject: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Collect process metadata for related PIDs without failing the whole page.

    Args:
        pids: Process ids to inspect.
        inject: Optional list of row dicts for deterministic tests.

    Returns:
        Dict with ``timestamp_utc``, ``processes`` (list of row dicts), and ``limitations``.
    """

    if inject is not None:
        return {
            "timestamp_utc": _now(),
            "processes": inject,
            "limitations": [
                "A directly observed process operation does not prove human intent.",
            ],
        }

    rows: list[ProcessSnapshotRow] = []
    try:
        import psutil
    except ImportError:
        return {
            "timestamp_utc": _now(),
            "processes": [],
            "errors": ["psutil_unavailable"],
            "limitations": [
                "A directly observed process operation does not prove human intent.",
            ],
        }

    for pid in sorted(set(int(p) for p in pids if p)):
        row = ProcessSnapshotRow(
            pid=pid,
            ppid=None,
            name=None,
            executable=None,
            command_line=None,
            username=None,
        )
        try:
            proc = psutil.Process(pid)
            try:
                row.name = proc.name()
            except (psutil.AccessDenied, PermissionError):
                row.access_denied_fields.append("name")
            try:
                row.ppid = proc.ppid()
            except (psutil.AccessDenied, PermissionError):
                row.access_denied_fields.append("ppid")
            try:
                row.executable = proc.exe()
            except (psutil.AccessDenied, PermissionError):
                row.access_denied_fields.append("executable")
            try:
                cmdline = proc.cmdline()
                row.command_line = " ".join(cmdline)[:500] if cmdline else None
            except (psutil.AccessDenied, PermissionError):
                row.access_denied_fields.append("command_line")
            try:
                row.username = proc.username()
            except (psutil.AccessDenied, PermissionError):
                row.access_denied_fields.append("username")
            try:
                for c in proc.net_connections(kind="tcp"):
                    if c.laddr:
                        lip = getattr(
                            c.laddr, "ip", c.laddr[0] if isinstance(c.laddr, tuple) else "?"
                        )
                        lport = getattr(
                            c.laddr, "port", c.laddr[1] if isinstance(c.laddr, tuple) else "?"
                        )
                        row.tcp_endpoints.append(f"{lip}:{lport}/{c.status}")
            except (psutil.AccessDenied, PermissionError):
                row.access_denied_fields.append("tcp_endpoints")
        except psutil.NoSuchProcess as exc:
            row.errors.append(str(exc))
        except Exception as exc:  # noqa: BLE001
            row.errors.append(str(exc)[:200])
        rows.append(row)

    return {
        "timestamp_utc": _now(),
        "processes": [r.to_dict() for r in rows],
        "limitations": [
            "A directly observed process operation does not prove human intent.",
            "Process metadata may be incomplete when access is denied.",
        ],
    }
