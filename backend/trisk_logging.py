"""Structured JSON logging for technology-risk worker and MCP surfaces."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

_LOGGER = logging.getLogger("trisk_platform")


def configure_trisk_logging(level: int = logging.INFO) -> None:
    """Configure trisk logging.
    
    Args:
        level: The level value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if not _LOGGER.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        _LOGGER.addHandler(handler)
    _LOGGER.setLevel(level)
    _LOGGER.propagate = False


def log_trisk(event: str, **fields: Any) -> None:
    """Emit one JSON log line for worker/MCP operations review."""
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "service": "trisk_platform",
        "event": event,
        **fields,
    }
    _LOGGER.info(json.dumps(payload, ensure_ascii=False, default=str))
