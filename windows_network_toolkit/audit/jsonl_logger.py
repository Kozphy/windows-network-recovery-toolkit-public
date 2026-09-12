"""Append-only JSONL audit logger for the ERP toolkit.

Module responsibility:
    Provides two functions — ``append_audit`` for writing canonically structured
    JSONL audit records, and ``read_audit_tail`` for reading the most-recent N
    records from the log.  Records are written sorted by key to aid diff and
    grep, and each gets an auto-assigned ``audit_id`` (UUID4) and ISO-8601
    timestamp if not already present in the input row.

System placement:
    Called by the incident pipeline on each run, by the ``audit`` CLI command,
    and by ``audit/__init__.py`` re-exports.  Default log path is
    ``logs/erp_decision_audit.jsonl`` relative to the current working directory.

Key invariants:
    Records are appended only; existing lines are never modified or deleted.
    ``audit_id`` uniqueness is guaranteed by UUID4 when the caller does not
    supply one.  Malformed lines in ``read_audit_tail`` are silently skipped.

Side effects:
    ``append_audit``: creates parent directories and opens the log file in append
    mode; may write to disk on every call.
    ``read_audit_tail``: reads the entire log file into memory.

Failure modes:
    ``append_audit`` raises ``OSError`` / ``PermissionError`` if the target path
    is not writable.  ``read_audit_tail`` returns ``[]`` if the file does not exist.

Audit Notes:
    This logger does not implement hash-chaining.  For custody-chain verification
    use ``src.platform_core.audit`` (``audit verify .audit/canonical_custody.jsonl``).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_DEFAULT_PATH = Path("logs/erp_decision_audit.jsonl")


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (second precision)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_audit(
    row: dict[str, Any],
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    """Append a structured audit record to the JSONL log file.

    Ensures the record has a unique ``audit_id``, an ISO-8601 ``timestamp``,
    a default ``actor``, ``action``, and ``target_type`` when the caller does
    not supply them.  Keys from the input ``row`` override defaults (except
    ``audit_id`` and ``timestamp`` which are already merged in).

    Args:
        row: Dict representing the audit event.  Recognised fields (used as
            defaults when absent): ``audit_id``, ``timestamp``, ``actor``,
            ``action``, ``target_type``, ``target_id`` (or ``incident_id``).
            All other keys are included verbatim.
        path: Override the default log file path.  Parent directories are
            created automatically.

    Returns:
        The complete, serialised audit record dict (same shape as the line
        written to the JSONL file).

    Side effects:
        Creates parent directories if absent.  Appends one line to the JSONL
        log file (``sort_keys=True``).

    Raises:
        OSError: If the file cannot be opened for writing.

    Audit Notes:
        The written record is the authoritative audit entry for this event.
        Each call must be traceable to a discrete pipeline action or operator
        command; do not batch-call this function for multiple distinct events.
    """
    target = path or _DEFAULT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "audit_id": str(row.get("audit_id") or uuid.uuid4()),
        "timestamp": str(row.get("timestamp") or _now_iso()),
        "actor": str(row.get("actor") or "erp_toolkit"),
        "action": str(row.get("action") or "pipeline_run"),
        "target_type": str(row.get("target_type") or "incident"),
        "target_id": str(row.get("target_id") or row.get("incident_id") or ""),
        **{k: v for k, v in row.items() if k not in {"audit_id", "timestamp"}},
    }
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def read_audit_tail(*, limit: int = 50, path: Path | None = None) -> list[dict[str, Any]]:
    """Return the most-recent ``limit`` valid records from the JSONL audit log.

    Reads the entire file and returns the last ``limit`` records.  Malformed
    JSONL lines and non-dict values are silently skipped.

    Args:
        limit: Maximum number of records to return, taken from the tail of the
            log.  Defaults to 50.
        path: Override the default log file path.

    Returns:
        A list of at most ``limit`` audit record dicts, in file order (oldest
        first within the returned slice).  Returns ``[]`` if the file does not
        exist or is empty.

    Side effects:
        Reads the entire log file into memory; no writes.
    """
    target = path or _DEFAULT_PATH
    if not target.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            blob = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(blob, dict):
            rows.append(blob)
    return rows[-limit:]
