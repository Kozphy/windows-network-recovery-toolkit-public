"""Safe process attribution for listener PIDs (best-effort; never labels malware).

Module responsibility:
    Collect readily observable, non-sensitive process fields (name, executable
    path, command line, parent PID, session owner) for a given PID using
    ``tasklist`` and ``Get-CimInstance Win32_Process``.  Access-denied fields
    are recorded in ``access_denied_fields``, not treated as fatal errors.

System placement:
    Called by ``localhost/runner.py`` when ``include_process=True`` or
    process fixture data is injected.  Results feed the ``nearby.py``
    PID-correlation logic and the diagnose report's ``processes`` field.

Key invariants:
    * Process identity is correlation only — it is never proof of malice,
      intent, or misconfiguration.  The ``limitations`` field in every
      ``to_dict()`` makes this explicit.
    * Command-line strings are capped at 500 characters to avoid accidentally
      capturing long credential-carrying invocations.
    * No process kill, suspension, or handle injection is attempted.

Side effects:
    Spawns ``tasklist`` and ``powershell`` subprocesses.  No filesystem
    writes; no system state modifications.

Failure modes:
    ``tasklist`` returning ``"INFO:"`` (PID not found) is treated as an
    empty result, not an error.  Access-denied CIM fields are listed in
    ``access_denied_fields`` so callers can adjust confidence accordingly.
"""

from __future__ import annotations

import csv
import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import StringIO
from typing import Any


@dataclass
class ProcessEvidence:
    """Safely collected process fields for a single PID.

    Attributes:
        pid: The target process ID.
        process_name: Image name from ``tasklist`` or CIM (e.g. ``"python.exe"``).
        executable_path: Full path from ``Win32_Process.ExecutablePath``; may
            be ``None`` when access is denied for Session 0 processes.
        command_line: Truncated command line (≤ 500 chars); ``None`` when
            access is denied.
        parent_pid: Parent process ID from ``Win32_Process.ParentProcessId``.
        parent_process_name: Image name of the parent, resolved via a second
            ``tasklist`` call.
        start_time: Process creation timestamp string from CIM.
        session_id: Windows session number from ``tasklist``.
        owner: Username/domain from ``tasklist`` ``/V`` output.
        access_denied_fields: Field names that could not be read due to
            access restrictions; indicates privilege gaps, not errors.
        collection_errors: Non-fatal collection error messages.
        evidence_source: How data was obtained (``"tasklist/cim"`` or
            ``"inject"`` for fixtures).
        timestamp_utc: ISO-8601 UTC timestamp at collection start.
    """

    pid: int | None = None
    process_name: str | None = None
    executable_path: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    parent_process_name: str | None = None
    start_time: str | None = None
    session_id: int | None = None
    owner: str | None = None
    access_denied_fields: list[str] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)
    evidence_source: str = "tasklist/cim"
    timestamp_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "executable_path": self.executable_path,
            "command_line": self.command_line,
            "parent_pid": self.parent_pid,
            "parent_process_name": self.parent_process_name,
            "start_time": self.start_time,
            "session_id": self.session_id,
            "owner": self.owner,
            "access_denied_fields": list(self.access_denied_fields),
            "collection_errors": list(self.collection_errors),
            "evidence_source": self.evidence_source,
            "timestamp_utc": self.timestamp_utc,
            "limitations": [
                "Process identity is correlation with the listening socket — not proof of malice or intent.",
            ],
        }


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_cmd(argv: list[str], *, run: Callable[..., Any], timeout: float) -> tuple[int, str]:
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
        return int(proc.returncode), ((proc.stdout or "") + (proc.stderr or "")).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def collect_process_evidence(
    pid: int,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: dict[str, Any] | None = None,
) -> ProcessEvidence:
    """Collect safely obtainable process fields for *pid*.

    Runs ``tasklist /FI "PID eq <pid>" /FO CSV /NH /V`` for image name,
    session, and owner, then ``Get-CimInstance Win32_Process`` via PowerShell
    for executable path, command line, and parent PID.  Each step is
    independent; access denied on one field does not abort others.

    Args:
        pid: The process ID to inspect.
        run: Injectable ``subprocess.run`` for testing.
        timeout: Per-subprocess wall-clock timeout in seconds.  Parent-name
            lookup uses ``min(timeout, 10.0)`` to avoid stalling the pipeline.
        inject: When not ``None``, builds a ``ProcessEvidence`` directly from
            the provided dict (fixture mode; no subprocesses are spawned).

    Returns:
        A ``ProcessEvidence`` dataclass.  Fields that could not be read are
        ``None``; their names appear in ``access_denied_fields``.

    Side effects:
        Spawns up to three subprocesses (tasklist × 2, powershell × 1).
        No filesystem writes; no system state modifications.

    Failure modes:
        JSON parse errors from CIM output are added to ``collection_errors``
        and the relevant fields remain ``None``.
    """

    ev = ProcessEvidence(pid=pid, timestamp_utc=_now())
    if inject is not None:
        for key in (
            "process_name",
            "executable_path",
            "command_line",
            "parent_pid",
            "parent_process_name",
            "start_time",
            "session_id",
            "owner",
        ):
            if key in inject:
                setattr(ev, key, inject[key])
        ev.access_denied_fields = list(inject.get("access_denied_fields") or [])
        ev.collection_errors = list(inject.get("collection_errors") or [])
        ev.evidence_source = str(inject.get("evidence_source") or "inject")
        return ev

    run_fn = run or subprocess.run
    code, out = _run_cmd(
        ["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH", "/V"],
        run=run_fn,
        timeout=timeout,
    )
    if code != 0 or not out.strip() or out.lower().startswith("info:"):
        ev.collection_errors.append(f"tasklist unavailable or empty for pid={pid}: {out[:200]}")
    else:
        # CSV: "name","pid","session name","session#","mem","status","user","cpu","window"
        try:
            row = next(csv.reader(StringIO(out.splitlines()[0])))
            if len(row) >= 2:
                ev.process_name = row[0]
            if len(row) >= 4:
                try:
                    ev.session_id = int(row[3])
                except ValueError:
                    ev.access_denied_fields.append("session_id")
            if len(row) >= 7 and row[6] and row[6] != "N/A":
                ev.owner = row[6]
        except Exception as exc:  # noqa: BLE001 — soft-fail field parse
            ev.collection_errors.append(f"tasklist parse: {exc}")

    # CIM for path/cmdline/parent — may Access Denied for Session 0
    ps = (
        f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={int(pid)}" '
        "-ErrorAction SilentlyContinue; if($p){"
        "$p | Select-Object Name,ExecutablePath,CommandLine,ParentProcessId,CreationDate | "
        "ConvertTo-Json -Compress}"
    )
    pcode, pout = _run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        run=run_fn,
        timeout=timeout,
    )
    if pcode != 0 or not pout.strip():
        if "access" in pout.lower() or "denied" in pout.lower():
            ev.access_denied_fields.extend(["executable_path", "command_line", "parent_pid"])
        elif pout.strip():
            ev.collection_errors.append(pout[:300])
    else:
        try:
            blob = json.loads(pout)
            if isinstance(blob, dict):
                ev.process_name = ev.process_name or blob.get("Name")
                path = blob.get("ExecutablePath")
                if path:
                    ev.executable_path = str(path)
                else:
                    ev.access_denied_fields.append("executable_path")
                cmd = blob.get("CommandLine")
                if cmd:
                    # Bound length — never store secrets-looking tokens beyond cap
                    ev.command_line = str(cmd)[:500]
                else:
                    ev.access_denied_fields.append("command_line")
                ppid = blob.get("ParentProcessId")
                if ppid is not None:
                    try:
                        ev.parent_pid = int(ppid)
                    except (TypeError, ValueError):
                        ev.access_denied_fields.append("parent_pid")
                created = blob.get("CreationDate")
                if created:
                    ev.start_time = str(created)
        except json.JSONDecodeError as exc:
            ev.collection_errors.append(f"cim json: {exc}")

    if ev.parent_pid:
        tcode, tout = _run_cmd(
            ["tasklist", "/FI", f"PID eq {int(ev.parent_pid)}", "/FO", "CSV", "/NH"],
            run=run_fn,
            timeout=min(timeout, 10.0),
        )
        if tcode == 0 and tout.strip() and not tout.lower().startswith("info:"):
            try:
                prow = next(csv.reader(StringIO(tout.splitlines()[0])))
                if prow:
                    ev.parent_process_name = prow[0]
            except Exception:  # noqa: BLE001
                ev.access_denied_fields.append("parent_process_name")

    # Deduplicate access_denied
    ev.access_denied_fields = sorted(set(ev.access_denied_fields))
    return ev
