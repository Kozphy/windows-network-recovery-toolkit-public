"""Append-only JSONL audit sink (local disk only; no upload).

Module responsibility:
    Persist one JSON-serializable audit event per line; callers own schema and timestamps.

System placement:
    Used by ``src.cli._audit``, ``src.network_recovery.audit``, and guardian/remediation
    paths that require durable local audit trails.

Key invariants:
    * Append-only — repeated calls add rows; not idempotent.
    * No network upload or remote sink from this module.
    * Creates parent directories before first write.

Side effects:
    * Creates ``path.parent`` if missing and appends one UTF-8 JSONL line to ``path``.

Audit Notes:
    Partial writes or disk exhaustion are file-level concerns; rotate or back up JSONL
    outside this API if line-count growth or parse failures are observed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    """Append one JSON object line to local audit log file.

    Side effects:
        - Creates parent directories if missing.
        - Appends one line to `path`.
        - Optionally records local observability metrics/logs (no external services).

    Idempotency:
        Not idempotent; repeated calls append additional entries.

    Args:
        path: Destination JSONL file path.
        payload: JSON-serializable audit event payload.

    Raises:
        TypeError: If payload contains non-serializable values.
        OSError: If file cannot be created or written.

    Audit Notes:
        Inspect line count growth and parse failures if disk fills or partial
        writes occur; recovery is file-level backup/rotation outside this API.
    """
    try:
        from src.platform_core.operability.context import correlation_fields, new_audit_id
        from src.platform_core.operability.events import record_audit_appended

        payload.setdefault("audit_id", new_audit_id())
        for key, value in correlation_fields().items():
            payload.setdefault(key, value)
        record_audit_appended(
            path=str(path),
            audit_id=str(payload["audit_id"]),
            trace_id=str(payload.get("trace_id")) if payload.get("trace_id") else None,
        )
    except ImportError:
        pass

    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False)
    try:
        from src.platform_core.io.locked_jsonl import append_jsonl_locked

        append_jsonl_locked(path, payload)
        return
    except ImportError:
        pass
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
