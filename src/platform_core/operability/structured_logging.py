"""Structured JSON logging — local stderr; disable with WNRT_STRUCTURED_LOG=0."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

from src.platform_core.operability.context import correlation_fields


def structured_logging_enabled() -> bool:
    """Return False when ``WNRT_STRUCTURED_LOG=0``."""
    return os.environ.get("WNRT_STRUCTURED_LOG", "1").lower() not in ("0", "false", "no")


def log_json(level: str, message: str, **fields: Any) -> dict[str, Any]:
    """Emit one structured JSON log record including trace_id and audit_id when set.

    Returns:
        The record dict (for tests).
    """
    record: dict[str, Any] = {
        "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "level": level.upper(),
        "message": message,
        **correlation_fields(),
        **fields,
    }
    if structured_logging_enabled():
        print(json.dumps(record, ensure_ascii=False), file=sys.stderr)
    return record
