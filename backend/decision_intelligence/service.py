"""Decision Intelligence service layer — replay and metrics aggregation.

Bridges HTTP routes to :mod:`platform_core.outcome_learning` for deterministic
replay digests and learning KPIs.
"""

from __future__ import annotations

from pathlib import Path

from platform_core.outcome_learning import (
    DecisionOutcome,
    compute_learning_metrics,
    evaluate_outcomes,
    metrics_payload,
    replay_outcomes,
)

from .models import MetricsResponse, ReplayRequest, ReplayResponse
from .store import DecisionIntelligenceStore, get_store


def run_replay(request: ReplayRequest, store: DecisionIntelligenceStore | None = None) -> ReplayResponse:
    """Replay fixture outcomes or stored API outcomes."""
    st = store or get_store()
    if request.fixture_path:
        result = replay_outcomes(Path(request.fixture_path))
    else:
        stored = st.list_all_outcomes()
        if stored:
            records = [
                DecisionOutcome(
                    outcome_id=row.outcome_id,
                    decision_id=row.decision_id,
                    outcome=row.outcome,
                    success=row.success,
                    predicted_success=row.predicted_success,
                    cost=row.cost,
                    time_to_resolution=row.time_to_resolution,
                    notes=row.notes,
                    recorded_at_utc=row.recorded_at_utc,
                )
                for row in stored
            ]
            evaluations = evaluate_outcomes(records)
            metrics = compute_learning_metrics(evaluations)
            from platform_core.outcome_learning.replay import content_digest

            digest = content_digest(
                {
                    "outcomes": [r.model_dump(mode="json") for r in records],
                    "metrics": metrics.model_dump(mode="json"),
                }
            )
            from platform_core.outcome_learning.models import OutcomeReplayResult

            result = OutcomeReplayResult(
                outcome_count=len(records),
                metrics=metrics,
                content_digest=digest,
                report_markdown="",
            )
        else:
            result = replay_outcomes()

    metrics = metrics_payload(result.metrics)
    excerpt = ""
    if result.report_markdown:
        excerpt = "\n".join(result.report_markdown.splitlines()[:12])

    return ReplayResponse(
        outcome_count=result.outcome_count,
        content_digest=result.content_digest,
        metrics=metrics,
        report_excerpt=excerpt,
    )


def get_metrics(store: DecisionIntelligenceStore | None = None) -> MetricsResponse:
    """Aggregate store counts and outcome-learning metrics.

    Args:
        store: Optional store override (defaults to :func:`get_store`).

    Returns:
        Store row counts, learning metrics, and active backend name.

    Notes:
        When no outcomes are stored, falls back to bundled fixture replay metrics.
    """
    st = store or get_store()
    outcomes = st.list_all_outcomes()
    if outcomes:
        records = [
            DecisionOutcome(
                outcome_id=row.outcome_id,
                decision_id=row.decision_id,
                outcome=row.outcome,
                success=row.success,
                predicted_success=row.predicted_success,
                cost=row.cost,
                time_to_resolution=row.time_to_resolution,
                notes=row.notes,
                recorded_at_utc=row.recorded_at_utc,
            )
            for row in outcomes
        ]
        learning = metrics_payload(compute_learning_metrics(evaluate_outcomes(records)))
    else:
        fixture_metrics = replay_outcomes().metrics
        learning = metrics_payload(fixture_metrics)

    return MetricsResponse(
        store=st.counts(),
        learning=learning,
        storage_backend=st.backend_name(),
    )
