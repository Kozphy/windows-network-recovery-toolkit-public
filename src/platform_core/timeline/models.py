"""Incident timeline entry model."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from src.platform_core.evidence.record import ConfidenceOrdinal


class TimelineEntry(BaseModel):
    """Represent the timeline entry type.

    Key fields:
        timestamp: Structured value carried by this type.
        event_type: Structured value carried by this type.
        actor: Structured value carried by this type.
        object: Structured value carried by this type.
        before_state: Structured value carried by this type.
        after_state: Structured value carried by this type.
        evidence_refs: Structured value carried by this type.
        confidence_level: Structured value carried by this type.

    Side effects:
        None.
    """
    timestamp: str
    event_type: str
    actor: str = "platform"
    object: str = ""
    before_state: str = ""
    after_state: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    confidence_level: ConfidenceOrdinal = "medium"
    limitations: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.
        """
        return self.model_dump(mode="json")
