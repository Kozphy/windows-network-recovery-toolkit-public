"""Forward-looking market event calendar (fixture-backed in v1)."""

from __future__ import annotations

import json
from pathlib import Path

from .models import MarketEvent


def default_calendar_path(repo_root: Path | None = None) -> Path:
    """Default calendar path.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    root = repo_root or Path.cwd()
    for candidate in (
        root / "fixtures" / "market_events" / "calendar.json",
        root / "tests" / "fixtures" / "market_events" / "calendar.json",
    ):
        if candidate.is_file():
            return candidate
    return root / "fixtures" / "market_events" / "calendar.json"


def load_calendar(path: Path | None = None) -> list[MarketEvent]:
    """Load calendar.

    Args:
        path: Filesystem path used by the operation.

    Returns:
        The list[MarketEvent] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    cal_path = path or default_calendar_path()
    raw = json.loads(cal_path.read_text(encoding="utf-8"))
    events_raw = raw.get("events") if isinstance(raw, dict) else raw
    if not isinstance(events_raw, list):
        raise ValueError(f"Invalid calendar fixture: {cal_path}")
    return [MarketEvent.model_validate(row) for row in events_raw]


def get_event(event_id: str, path: Path | None = None) -> MarketEvent:
    """Get event.

    Args:
        event_id: The event id value supplied by the caller.
        path: Filesystem path used by the operation.

    Returns:
        The MarketEvent result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    for event in load_calendar(path):
        if event.event_id == event_id:
            return event
    raise KeyError(f"Unknown event_id: {event_id}")
