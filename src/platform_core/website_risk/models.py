"""Website risk scoring models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class WebsiteRiskLevel(StrEnum):
    """Represent the website risk level enum.

    Variants:
        LOW: Structured value carried by this enum.
        MEDIUM: Structured value carried by this enum.
        HIGH: Structured value carried by this enum.
        UNKNOWN: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


class WebsiteRiskEvidence(BaseModel):
    """Represent the website risk evidence type.

    Key fields:
        signal: Structured value carried by this type.
        observed: Structured value carried by this type.
        weight: Structured value carried by this type.
        detail: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    signal: str
    observed: str
    weight: float = 0.0
    detail: str = ""


class WebsiteRiskResult(BaseModel):
    """Represent the website risk result type.

    Key fields:
        assessment_id: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        url: Structured value carried by this type.
        final_url: Structured value carried by this type.
        risk_level: Structured value carried by this type.
        score: Structured value carried by this type.
        evidence: Structured value carried by this type.
        reputation_plugins_used: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    assessment_id: str
    timestamp_utc: str
    url: str
    final_url: str = ""
    risk_level: WebsiteRiskLevel = WebsiteRiskLevel.UNKNOWN
    score: float = 0.0
    evidence: list[WebsiteRiskEvidence] = Field(default_factory=list)
    reputation_plugins_used: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return self.model_dump(mode="json")
