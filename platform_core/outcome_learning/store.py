"""Load recorded decision outcomes from versioned JSON fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from .models import DecisionOutcome


def default_outcomes_path(repo_root: Path | None = None) -> Path:
    """Default outcomes path for toolkit workflows.

    Args:
        repo_root: Value supplied by the caller for repo root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    root = repo_root or Path.cwd()
    for candidate in (
        root / "fixtures" / "outcome_learning" / "outcomes.json",
        root / "tests" / "fixtures" / "outcome_learning" / "outcomes.json",
    ):
        if candidate.is_file():
            return candidate
    return root / "fixtures" / "outcome_learning" / "outcomes.json"


def load_outcomes(path: Path | None = None) -> list[DecisionOutcome]:
    """Load outcomes from a JSON fixture (list or ``{outcomes: [...]}``).

    Args:
        path: Fixture path; searches default locations when omitted.

    Returns:
        Outcomes sorted by ``(decision_id, outcome_id)``.

    Raises:
        FileNotFoundError: When the fixture file is missing.
        ValueError: When JSON shape is invalid.
    """
    outcome_path = path or default_outcomes_path()
    if not outcome_path.is_file():
        raise FileNotFoundError(outcome_path)
    raw = json.loads(outcome_path.read_text(encoding="utf-8"))
    rows = raw.get("outcomes") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise ValueError(f"invalid outcomes fixture: {outcome_path}")
    records = [DecisionOutcome.model_validate(row) for row in rows]
    return sorted(records, key=lambda row: (row.decision_id, row.outcome_id))
