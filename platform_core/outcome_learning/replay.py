"""Deterministic replay of outcome learning over fixtures.

Side effects:
    Reads JSON fixture from disk when ``path`` is provided; no writes.

Output guarantees:
    Identical fixture inputs yield identical ``content_digest``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .evaluation import evaluate_outcomes
from .learning import compute_learning_metrics
from .models import OutcomeReplayResult
from .reports import build_learning_report, report_to_markdown
from .store import load_outcomes


def canonical_json(payload: Any) -> str:
    """Provide canonical json behavior for toolkit workflows.

    Args:
        payload: Value supplied by the caller for payload.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def content_digest(payload: Any) -> str:
    """Provide content digest behavior for toolkit workflows.

    Args:
        payload: Value supplied by the caller for payload.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def replay_outcomes(path: Path | None = None) -> OutcomeReplayResult:
    """Replay Decision → Outcome → Evaluation → Learning on a fixed fixture.

    Args:
        path: Optional outcomes JSON path; defaults to bundled fixture.

    Returns:
        Metrics, markdown report excerpt, and SHA-256 ``content_digest``.
    """
    records = load_outcomes(path)
    evaluations = evaluate_outcomes(records)
    metrics = compute_learning_metrics(evaluations)
    digest = content_digest(
        {
            "outcomes": [row.model_dump(mode="json") for row in records],
            "metrics": metrics.model_dump(mode="json"),
        }
    )
    report = build_learning_report(evaluations, content_digest=digest)
    return OutcomeReplayResult(
        outcome_count=len(records),
        metrics=metrics,
        content_digest=digest,
        report_markdown=report_to_markdown(report),
    )
