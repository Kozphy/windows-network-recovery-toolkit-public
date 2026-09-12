"""Base analyst provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.platform_core.ai_risk_analyst.models import AIRecommendation, AnalystEvidenceBundle


class AnalystProvider(ABC):
    """Represent the analyst provider type.

    Key fields:
        name: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    name: str = "base"

    @abstractmethod
    def analyze(self, bundle: AnalystEvidenceBundle) -> AIRecommendation:
        """Produce advisory recommendation from structured evidence."""
