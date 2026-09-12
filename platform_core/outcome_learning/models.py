"""Outcome learning models — Decision → Outcome → Evaluation → Learning.

Distinct from :class:`platform_core.decision_domain.DecisionOutcome` (expected outcome
on a decision snapshot). This module records **observed** outcomes after the fact.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso
from platform_core.reasoning_models import new_id

OutcomeClassification = Literal[
    "true_positive",
    "true_negative",
    "false_positive",
    "false_negative",
]


class DecisionOutcome(BaseModel):
    """Recorded result for a prior decision (ground truth + cost telemetry)."""

    decision_id: str
    outcome: str
    success: bool
    cost: float = Field(ge=0.0, default=0.0)
    time_to_resolution: float = Field(ge=0.0, default=0.0)
    notes: str = ""
    outcome_id: str = Field(default_factory=lambda: new_id("oc"))
    predicted_success: bool = True
    recorded_at_utc: str = Field(default_factory=utc_now_iso)
    schema_version: str = "outcome_learning.v1"


class OutcomeEvaluation(BaseModel):
    """Evaluation of one recorded outcome against the decision prediction."""

    outcome_id: str
    decision_id: str
    actual_success: bool
    predicted_success: bool
    correct: bool
    classification: OutcomeClassification
    cost: float = Field(ge=0.0)
    time_to_resolution: float = Field(ge=0.0)
    notes: str = ""


class LearningMetrics(BaseModel):
    """Aggregate learning metrics over a batch of evaluations."""

    decision_accuracy: float = Field(ge=0.0, le=1.0)
    decision_precision: float = Field(ge=0.0, le=1.0)
    decision_recall: float = Field(ge=0.0, le=1.0)
    average_cost: float = Field(ge=0.0)
    average_time_to_resolution: float = Field(ge=0.0)
    sample_count: int = Field(ge=0)
    true_positives: int = Field(ge=0, default=0)
    true_negatives: int = Field(ge=0, default=0)
    false_positives: int = Field(ge=0, default=0)
    false_negatives: int = Field(ge=0, default=0)


class LearningReport(BaseModel):
    """Full learning report for audit and replay."""

    schema_version: str = "outcome_learning.report.v1"
    metrics: LearningMetrics
    evaluations: list[OutcomeEvaluation] = Field(default_factory=list)
    content_digest: str = ""
    summary: str = ""


class OutcomeReplayResult(BaseModel):
    """Deterministic replay artifact over a fixed outcome set."""

    outcome_count: int
    metrics: LearningMetrics
    content_digest: str
    report_markdown: str = ""
