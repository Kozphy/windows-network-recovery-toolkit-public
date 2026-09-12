"""Unified JSONL audit logging under ``.audit/`` — soft-fail on write errors.

Module responsibility:
    Append-only audit rows for CLI commands and read merged JSONL for analytics/timeline.

System placement:
    Used by ``proxy_remediation``, ``watch``, ``analytics_pipeline``, and governance exports.
    Directory override via ``WNT_AUDIT_DIR`` environment variable (default ``.audit``).

Key invariants:
    * Append-only — no in-place updates or deletes.
    * Timestamps use UTC ISO-8601 with ``Z`` suffix.
    * Write failures return ``(False, error_message)`` — callers must not assume success.

Side effects:
    Creates ``.audit/`` directory and appends JSONL lines on successful writes.

Idempotency:
    Each append adds a new line — repeated calls create distinct audit events.

Failure modes:
    ``OSError`` on write returns soft-fail tuple; ``read_audit_logs`` skips malformed JSON lines.

Audit Notes:
    * Soft-fail writes may leave operators without audit evidence — check ``audit_error`` fields.
    * Recovery: verify disk permissions on ``WNT_AUDIT_DIR`` and re-run command.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from windows_network_toolkit.models import AuditEvent


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_dir() -> Path:
    """Return audit directory from ``WNT_AUDIT_DIR`` or default ``.audit``."""
    raw = os.environ.get("WNT_AUDIT_DIR", ".audit")
    return Path(raw)


def append_audit_event(
    event: AuditEvent,
    *,
    log_name: str = "events.jsonl",
) -> tuple[bool, str | None]:
    """Append a typed audit event to JSONL.

    Args:
        event: Structured ``AuditEvent`` to serialize.
        log_name: Filename under audit dir (e.g. ``proxy-disable.jsonl``).

    Returns:
        ``(True, None)`` on success; ``(False, error_message)`` on ``OSError``.

    Side effects:
        Creates parent directory and appends one JSON line.
    """
    path = audit_dir() / log_name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        return True, None
    except OSError as exc:
        return False, str(exc)


def append_audit_dict(
    payload: dict[str, Any],
    *,
    log_name: str = "events.jsonl",
) -> tuple[bool, str | None]:
    """Append a dict payload with auto ``timestamp_utc`` to JSONL.

    Args:
        payload: Audit fields without timestamp (added automatically).
        log_name: Target JSONL filename under audit dir.

    Returns:
        Same tuple contract as ``append_audit_event``.
    """
    path = audit_dir() / log_name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        row = {"timestamp_utc": _now(), **payload}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        return True, None
    except OSError as exc:
        return False, str(exc)


def read_audit_logs(*, pattern: str = "*.jsonl") -> list[dict[str, Any]]:
    """Read and merge JSONL audit files matching ``pattern``.

    Args:
        pattern: Glob under audit dir (default all ``*.jsonl``).

    Returns:
        Parsed rows in sorted file order; skips blank lines and invalid JSON lines.

    Side effects:
        Read-only filesystem access.
    """
    base = audit_dir()
    if not base.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(base.glob(pattern)):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows
