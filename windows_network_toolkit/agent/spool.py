"""Local JSONL spool for read-only endpoint agent evidence events.

Module responsibility:
    Manage the append-only JSONL spool file that the read-only agent uses to
    persist evidence events between collection cycles.  Provides path
    resolution, single-event append, full-read, last-event access, and a
    status summary.

System placement:
    Used exclusively by ``agent.read_only`` (``collect_once``,
    ``get_health_status``, ``get_spool_status``).  The spool file is a local
    custody artefact; it is not uploaded or synced unless a separate path is
    configured outside this module.

Key invariants:
    * All operations on the spool are append-only or read-only; no existing
      line is ever modified or deleted by this module.
    * ``spool_status`` always returns ``read_only=True`` to make the
      read-only invariant explicit in every status response.
    * Path resolution precedence: CLI override → ``WNRT_AGENT_SPOOL`` env var
      → ``$CWD/.audit/agent-spool.jsonl``.

Side effects:
    * ``append_spool_event`` delegates to ``src.logging.audit.append_jsonl``,
      which writes one JSON line to the spool file (creating it if absent).
    * ``read_spool_lines`` and ``read_last_spool_event`` read from disk.

Failure modes:
    ``append_spool_event`` raises ``OSError`` when the spool path is not
    writable.  ``read_spool_lines`` raises ``json.JSONDecodeError`` on
    malformed lines.

Audit Notes:
    Spool files are local custody records.  Correlate ``collected_at_utc``
    and ``audit_id`` fields with platform audit JSONL entries to trace a
    collection cycle end-to-end.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.logging.audit import append_jsonl

DEFAULT_SPOOL_RELATIVE = Path(".audit") / "agent-spool.jsonl"


def resolve_spool_path(override: str | None = None) -> Path:
    """Resolve spool file path from CLI flag, env, or default."""
    if override:
        return Path(override).expanduser().resolve()
    env = os.environ.get("WNRT_AGENT_SPOOL")
    if env:
        return Path(env).expanduser().resolve()
    return Path.cwd() / DEFAULT_SPOOL_RELATIVE


def append_spool_event(path: Path, record: dict[str, Any]) -> None:
    """Append one evidence event row to the agent spool (append-only)."""
    append_jsonl(path, record)


def read_spool_lines(path: Path) -> list[dict[str, Any]]:
    """Read all JSONL rows from spool; returns empty list when file missing."""
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            rows.append(json.loads(stripped))
    return rows


def read_last_spool_event(path: Path) -> dict[str, Any] | None:
    """Return the last parsed spool row, or None when spool is empty."""
    rows = read_spool_lines(path)
    return rows[-1] if rows else None


def spool_status(path: Path) -> dict[str, Any]:
    """Summarize spool depth and last event metadata (read-only)."""
    rows = read_spool_lines(path)
    last = rows[-1] if rows else None
    return {
        "spool_path": str(path),
        "exists": path.is_file(),
        "event_count": len(rows),
        "last_event_kind": (last or {}).get("event_kind"),
        "last_collected_at_utc": (last or {}).get("collected_at_utc"),
        "last_endpoint_id": (last or {}).get("endpoint_id"),
        "read_only": True,
    }
