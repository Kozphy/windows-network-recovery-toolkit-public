"""Audit JSONL reader."""

from __future__ import annotations

import json
from pathlib import Path

from src.platform_core.audit.schema import validate_audit_record


def read_audit_tail(*, path: Path, limit: int = 100) -> list[dict]:
    """Read audit tail.

    Args:
        path: path supplied by the caller.
        limit: limit supplied by the caller.

    Returns:
        The computed `list[dict]` value.

    Side effects:
        Reads data from the requested source.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
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
    """Read audit for decision.

    Args:
        path: path supplied by the caller.
        decision_id: decision id supplied by the caller.

    Returns:
        The computed `list[dict]` value.

    Side effects:
        Reads data from the requested source.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return [r for r in read_audit_tail(path=path, limit=10_000) if r.get("decision_id") == decision_id]
