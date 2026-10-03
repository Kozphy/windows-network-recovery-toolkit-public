"""Audit JSONL reader."""

from __future__ import annotations

import json
from pathlib import Path

from src.platform_core.audit.schema import validate_audit_record


def read_audit_tail(*, path: Path, limit: int = 100) -> list[dict]:
    """Read valid audit records from the end of a JSONL file.

    Malformed or structurally incomplete lines are skipped so investigative
    readers can inspect a partially written file without raising. Use the
    chain verifier for authoritative integrity checks.

    Args:
        path: Audit JSONL path.
        limit: Maximum number of valid records to return.

    Returns:
        The last ``limit`` structurally valid records, or an empty list when
        the file is absent.
    """
    if not path.is_file():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            blob = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(blob, dict) and validate_audit_record(blob):
            rows.append(blob)
    return rows[-limit:]


def read_audit_for_decision(*, path: Path, decision_id: str) -> list[dict]:
    """Return recent audit records associated with one decision identifier.

    Args:
        path: Audit JSONL path.
        decision_id: Decision identifier to match.

    Returns:
        Matching records from the investigative tail reader.

    Side effects:
        Reads the audit file through :func:`read_audit_tail`.
    """
    return [
        r for r in read_audit_tail(path=path, limit=10_000) if r.get("decision_id") == decision_id
    ]
