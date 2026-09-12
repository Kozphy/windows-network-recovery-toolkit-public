"""Wall-clock timestamps for audits (always UTC-aware ISO strings)."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now_iso() -> str:
    """Return ``datetime.now(timezone.utc).isoformat()`` for JSONL timestamps."""
    return datetime.now(UTC).isoformat()
