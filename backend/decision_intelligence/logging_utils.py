"""Structured JSON logging for Decision Intelligence API."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

_LOGGER = logging.getLogger("decision_intelligence")


def configure_structured_logging(level: int = logging.INFO) -> None:
    """Configure structured logging.
    
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


def log_structured(event: str, **fields: Any) -> None:
    """Emit one JSON log line for audit and operations review.

    Args:
        event: Short event name (e.g. ``create_decision``, ``replay``).
        **fields: Additional structured fields (operator id, ids, counts).

    Side effects:
        Writes to the ``decision_intelligence`` logger (stdout by default).
    """
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "service": "decision_intelligence_api",
        "event": event,
        **fields,
    }
    _LOGGER.info(json.dumps(payload, ensure_ascii=False, default=str))
