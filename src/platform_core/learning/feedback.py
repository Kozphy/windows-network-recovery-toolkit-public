"""Learning feedback records."""

from __future__ import annotations

import uuid

from platform_core.models import utc_now_iso
from src.platform_core.contracts import LearningRecord
from src.platform_core.outcome.metrics import compute_metrics


def record_feedback(*, decision_id: str, feedback_type: str = "outcome_observed") -> LearningRecord:
    """Record feedback.

    Args:
        decision_id: decision id supplied by the caller.
        feedback_type: feedback type supplied by the caller.

    Returns:
        The computed `LearningRecord` value.

    Side effects:
        Records data in the configured store or telemetry sink.
    """
    return LearningRecord(
        record_id=f"lrn-{uuid.uuid4().hex[:12]}",
        decision_id=decision_id,
        created_at=utc_now_iso(),
        feedback_type=feedback_type,
        metrics_snapshot=compute_metrics(),
    )
