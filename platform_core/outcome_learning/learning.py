"""Aggregate evaluation batches into learning metrics (accuracy, precision, recall)."""

from __future__ import annotations

from .models import LearningMetrics, OutcomeEvaluation


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def compute_learning_metrics(evaluations: list[OutcomeEvaluation]) -> LearningMetrics:
    """Compute accuracy, precision, recall, and average cost (deterministic).

    Args:
        evaluations: Classified outcome rows.

    Returns:
        Aggregate metrics; zeroed fields when ``evaluations`` is empty.
    """
    if not evaluations:
        return LearningMetrics(
            decision_accuracy=0.0,
            decision_precision=0.0,
            decision_recall=0.0,
            average_cost=0.0,
            average_time_to_resolution=0.0,
            sample_count=0,
        )

    tp = sum(1 for row in evaluations if row.classification == "true_positive")
    tn = sum(1 for row in evaluations if row.classification == "true_negative")
    fp = sum(1 for row in evaluations if row.classification == "false_positive")
    fn = sum(1 for row in evaluations if row.classification == "false_negative")

    correct = tp + tn
    n = len(evaluations)
    total_cost = sum(row.cost for row in evaluations)
    total_time = sum(row.time_to_resolution for row in evaluations)

    return LearningMetrics(
        decision_accuracy=_safe_ratio(correct, n),
        decision_precision=_safe_ratio(tp, tp + fp),
        decision_recall=_safe_ratio(tp, tp + fn),
        average_cost=round(total_cost / n, 4),
        average_time_to_resolution=round(total_time / n, 4),
        sample_count=n,
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
    )
