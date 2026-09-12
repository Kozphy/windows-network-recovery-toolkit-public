"""Outcome learning — evaluate recorded decisions against ground truth.

.. deprecated::
    For new MDP code use :mod:`src.platform.outcome_engine`. This module remains
    for Decision Intelligence API compatibility.

Pipeline::

    DecisionOutcome → OutcomeEvaluation → LearningMetrics → replay digest

Distinct from expected outcomes on decision snapshots
(:mod:`platform_core.decision_domain`). Used by the Decision Intelligence API
replay/metrics endpoints.
"""

from .evaluation import classify_outcome, evaluate_outcome, evaluate_outcomes
from .learning import compute_learning_metrics
from .models import (
    DecisionOutcome,
    LearningMetrics,
    LearningReport,
    OutcomeEvaluation,
    OutcomeReplayResult,
)
from .replay import content_digest, replay_outcomes
from .reports import build_learning_report, metrics_payload, report_to_json, report_to_markdown
from .store import default_outcomes_path, load_outcomes

__all__ = [
    "DecisionOutcome",
    "LearningMetrics",
    "LearningReport",
    "OutcomeEvaluation",
    "OutcomeReplayResult",
    "build_learning_report",
    "classify_outcome",
    "compute_learning_metrics",
    "content_digest",
    "default_outcomes_path",
    "evaluate_outcome",
    "evaluate_outcomes",
    "load_outcomes",
    "metrics_payload",
    "replay_outcomes",
    "report_to_json",
    "report_to_markdown",
]
