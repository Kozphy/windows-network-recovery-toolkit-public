"""Outcome learning metrics."""

from __future__ import annotations

from statistics import mean, median
from typing import Any

from src.platform_core.outcome.store import load_outcomes


def compute_metrics(*, baseline_mttr_seconds: float = 3600.0) -> dict[str, Any]:
    """Compute metrics.

    Args:
        baseline_mttr_seconds: baseline mttr seconds supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    outcomes = load_outcomes()
    if not outcomes:
        return {
            "decision_accuracy": 0.0,
            "false_positive_rate": 0.0,
            "policy_block_rate": 0.0,
            "mean_time_to_resolution": 0.0,
            "median_time_to_resolution": 0.0,
            "mttr_delta_baseline": 0.0,
            "approval_rate": 0.0,
            "rollback_rate": 0.0,
            "sample_size": 0,
        }

    successful = [o for o in outcomes if o.was_successful is True]
    false_pos = [o for o in outcomes if o.was_false_positive is True]
    blocked = [o for o in outcomes if o.was_blocked_by_policy]
    ttls = [
        o.time_to_resolution_seconds for o in outcomes if o.time_to_resolution_seconds is not None
    ]
    approvals = [
        o for o in outcomes if o.operator_action and "approve" in o.operator_action.lower()
    ]
    rollbacks = [o for o in outcomes if "rollback" in (o.actual_outcome or "").lower()]

    n = len(outcomes)
    mean_mttr = mean(ttls) if ttls else 0.0
    med_mttr = median(ttls) if ttls else 0.0

    return {
        "decision_accuracy": len(successful) / n if n else 0.0,
        "false_positive_rate": len(false_pos) / n if n else 0.0,
        "policy_block_rate": len(blocked) / n if n else 0.0,
        "mean_time_to_resolution": mean_mttr,
        "median_time_to_resolution": med_mttr,
        "mttr_delta_baseline": baseline_mttr_seconds - mean_mttr if mean_mttr else 0.0,
        "approval_rate": len(approvals) / n if n else 0.0,
        "rollback_rate": len(rollbacks) / n if n else 0.0,
        "sample_size": n,
    }
