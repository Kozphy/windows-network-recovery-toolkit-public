"""Evaluate recorded outcomes against decision predictions.

Classifies each outcome as true/false positive/negative based on
``predicted_success`` vs actual ``success``.
"""

from __future__ import annotations

from .models import DecisionOutcome, OutcomeClassification, OutcomeEvaluation


def classify_outcome(*, predicted_success: bool, actual_success: bool) -> OutcomeClassification:
    """Map prediction vs actual success to a four-way classification label."""
    if predicted_success and actual_success:
        return "true_positive"
    if not predicted_success and not actual_success:
        return "true_negative"
    if predicted_success and not actual_success:
        return "false_positive"
    return "false_negative"


def evaluate_outcome(record: DecisionOutcome) -> OutcomeEvaluation:
    """Evaluate a single :class:`DecisionOutcome` record."""
    classification = classify_outcome(
        predicted_success=record.predicted_success,
        actual_success=record.success,
    )
    return OutcomeEvaluation(
        outcome_id=record.outcome_id,
        decision_id=record.decision_id,
        actual_success=record.success,
        predicted_success=record.predicted_success,
        correct=record.predicted_success == record.success,
        classification=classification,
        cost=record.cost,
        time_to_resolution=record.time_to_resolution,
        notes=record.notes,
    )


def evaluate_outcomes(records: list[DecisionOutcome]) -> list[OutcomeEvaluation]:
    """Evaluate all outcomes in stable decision_id order."""
    ordered = sorted(records, key=lambda row: (row.decision_id, row.outcome_id))
    return [evaluate_outcome(record) for record in ordered]
