"""Structured user feedback for calibration (local JSONL)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .audit import append_jsonl

FeedbackState = Literal["true", "false", "unknown"]


@dataclass(frozen=True)
class FeedbackRecord:
    """Structured user outcome feedback tied to one diagnosis action.

    Attributes:
        diagnosis_id: Diagnosis identifier the feedback references.
        recommended_action: Action/script user attempted.
        user_feedback_fixed: Outcome state (`true`/`false`/`unknown`).
        notes: Optional free-text notes from user/operator.
    """

    diagnosis_id: str
    recommended_action: str
    user_feedback_fixed: FeedbackState
    notes: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize feedback record into append-only event payload.

        Timezone assumptions:
            - `timestamp` is generated in UTC ISO-8601 format.
        """
        return {
            "type": "feedback",
            "feedback_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "diagnosis_id": self.diagnosis_id,
            "recommended_action": self.recommended_action,
            "user_feedback_fixed": self.user_feedback_fixed,
            "notes": self.notes,
        }


def append_feedback(path: Path, record: FeedbackRecord) -> None:
    """Append one feedback event to JSONL feedback log.

    Side effects:
        Same as `append_jsonl` (creates parents, appends one serialized line).

    Args:
        path: Destination JSONL file path (typically ``logs/decision_feedback.jsonl``).
        record: Feedback record to persist.

    Raises:
        TypeError / OSError: Propagated from `append_jsonl`.
    """
    append_jsonl(path, record.to_dict())
