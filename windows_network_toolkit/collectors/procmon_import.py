"""Procmon CSV import into dashboard evidence events (no Procmon GUI control).

Module responsibility:
    Parse exported Procmon CSV rows for successful Internet Settings proxy RegSetValue
    operations and normalize them into ``EvidenceEvent`` objects for the evidence store.

System placement:
    CLI ``procmon-import``; does not launch or control Procmon.exe.

Key invariants:
    * Only SUCCESS (or SUCCESSFULL) RegSetValue/SetValue rows on Internet Settings
      proxy-related value paths are imported.
    * Import never writes the Windows registry.

Side effects:
    * Reads the CSV file from disk; callers append events to the store.

Failure modes:
    * ``ProcmonImportError`` for missing file, empty CSV, or missing Operation/Path columns.

Audit Notes:
    * Procmon timestamps are preserved as strings when present; otherwise UTC now is used.
    * A RegSetValue row is direct write evidence for that process — still not human intent.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from windows_network_toolkit.storage.events import (
    DEFAULT_LIMITATIONS,
    EvidenceEvent,
    new_event_id,
    utc_now_iso,
)


class ProcmonImportError(ValueError):
    """Malformed or unreadable Procmon CSV."""

    def __init__(self, message: str, *, code: str = "PROCMON_CSV_INVALID") -> None:
        """Initialize a Procmon import validation error.

        Args:
            message: Human-readable error detail.
            code: Stable machine-readable error code.

        Returns:
            None.

        Side effects:
            Stores ``code`` and ``message`` on the exception instance."""
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        """Serialise the error as a plain dict with ``code`` and ``message`` keys."""
        return {"code": self.code, "message": self.message}


def _norm_header(name: str) -> str:
    """Normalise a CSV header name for case- and separator-insensitive lookup."""
    return name.strip().lower().replace("_", " ")


_PROXY_TAILS = ("proxyenable", "proxyserver", "autoconfigurl", "autodetect", "proxyoverride")


def import_procmon_csv(path: str | Path) -> list[EvidenceEvent]:
    """Parse Procmon CSV and return evidence events for relevant RegSetValue rows.

    Raises:
        ProcmonImportError: When the file is missing, empty, or lacks required columns.
    """

    csv_path = Path(path)
    if not csv_path.is_file():
        raise ProcmonImportError(f"Procmon CSV not found: {csv_path}", code="FILE_NOT_FOUND")

    try:
        text = csv_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ProcmonImportError(f"Unable to read CSV: {exc}", code="READ_FAILED") from exc

    if not text.strip():
        raise ProcmonImportError("Procmon CSV is empty.", code="EMPTY_CSV")

    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        raise ProcmonImportError("Procmon CSV has no header row.", code="MISSING_HEADER")

    remap = {_norm_header(h): h for h in reader.fieldnames}

    def col(*candidates: str) -> str | None:
        """Resolve the first matching CSV column from candidate header names.

        Args:
            candidates: Header names to match after normalization.

        Returns:
            Original CSV header string when matched, otherwise ``None``.

        Side effects:
            None."""
        for c in candidates:
            key = remap.get(_norm_header(c))
            if key:
                return key
        return None

    c_op = col("operation")
    c_path = col("path", "registry path", "name")
    if not c_op or not c_path:
        raise ProcmonImportError(
            "Procmon CSV must include Operation and Path columns.",
            code="MISSING_COLUMNS",
        )

    c_time = col("time of day", "time", "date time", "utc time")
    c_pid = col("pid", "process id")
    c_proc = col("process name", "process", "application")
    c_result = col("result")
    c_detail = col("detail", "detail data")

    events: list[EvidenceEvent] = []
    for row in reader:
        op = str(row.get(c_op) or "").lower()
        if "regsetvalue" not in op and "setvalue" not in op:
            continue
        rp = str(row.get(c_path) or "").lower()
        if "internet settings" not in rp:
            continue
        if not any(t in rp for t in _PROXY_TAILS):
            continue
        res = str(row.get(c_result or "") or "").upper()
        if res and "SUCCESS" not in res and "SUCCESSFULL" not in res:
            continue

        pid_raw = row.get(c_pid or "") if c_pid else None
        pid = int(pid_raw) if isinstance(pid_raw, str) and pid_raw.strip().isdigit() else None
        proc_name = str(row.get(c_proc) or "").strip() if c_proc else ""
        detail = str(row.get(c_detail) or "")[:300] if c_detail else ""
        time_s = str(row.get(c_time) or "").strip() if c_time else ""

        events.append(
            EvidenceEvent(
                event_id=new_event_id(),
                timestamp=utc_now_iso(),
                source="procmon_csv",
                event_type="registry_setvalue",
                severity="warning",
                summary=f"Procmon RegSetValue by {proc_name or 'unknown'} on {row.get(c_path)}",
                data={
                    "observed_time": time_s,
                    "process_name": proc_name or None,
                    "pid": pid,
                    "operation": row.get(c_op),
                    "path": row.get(c_path),
                    "result": row.get(c_result) if c_result else None,
                    "detail": detail,
                    "import_file": str(csv_path),
                },
                classification=None,
                proof_tier="T3_BEHAVIORAL_REPRODUCTION",
                confidence=None,
                limitations=list(DEFAULT_LIMITATIONS)
                + [
                    "Procmon CSV rows are strong local write evidence within the capture window — not intent proof.",
                ],
            )
        )
    return events


def import_procmon_csv_summary(path: str | Path) -> dict[str, Any]:
    """Import CSV and return a JSON-serializable summary for CLI stdout.

    Args:
        path: Procmon CSV path.

    Returns:
        Dict with ``events_imported``, ``events`` (list of ``to_dict``), and limitations.
        ``policy.decision`` is always ``PREVIEW`` / read-only for this command.

    Raises:
        ProcmonImportError: Propagated from ``import_procmon_csv``.
    """

    events = import_procmon_csv(path)
    return {
        "command": "procmon-import",
        "path": str(path),
        "events_imported": len(events),
        "events": [e.to_dict() for e in events],
        "limitations": list(DEFAULT_LIMITATIONS),
        "policy": {"decision": "PREVIEW", "read_only": True},
    }
