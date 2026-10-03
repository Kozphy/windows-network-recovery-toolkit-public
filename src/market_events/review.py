"""Post-event review loader and validation."""

from __future__ import annotations

import json
from pathlib import Path

from .models import PostEventReview


def default_reviews_path(repo_root: Path | None = None) -> Path:
    """Default reviews path.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    root = repo_root or Path.cwd()
    for candidate in (
        root / "fixtures" / "market_events" / "reviews.json",
        root / "tests" / "fixtures" / "market_events" / "reviews.json",
    ):
        if candidate.is_file():
            return candidate
    return root / "fixtures" / "market_events" / "reviews.json"


def load_reviews(path: Path | None = None) -> list[PostEventReview]:
    """Load reviews.

    Args:
        path: Filesystem path used by the operation.

    Returns:
        The list[PostEventReview] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    rev_path = path or default_reviews_path()
    if not rev_path.is_file():
        return []
    raw = json.loads(rev_path.read_text(encoding="utf-8"))
    rows = raw.get("reviews") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise ValueError(f"Invalid reviews fixture: {rev_path}")
    return [PostEventReview.model_validate(row) for row in rows]


def get_review(event_id: str, path: Path | None = None) -> PostEventReview:
    """Get review.

    Args:
        event_id: The event id value supplied by the caller.
        path: Filesystem path used by the operation.

    Returns:
        The PostEventReview result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    for review in load_reviews(path):
        if review.event_id == event_id:
            return review
    raise KeyError(f"No post-event review for event_id: {event_id}")
