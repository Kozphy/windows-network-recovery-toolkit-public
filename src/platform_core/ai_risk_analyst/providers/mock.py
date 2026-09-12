"""Deterministic mock analyst for tests and CI."""

from __future__ import annotations

from src.platform_core.ai_risk_analyst.models import AIRecommendation, AnalystEvidenceBundle
from src.platform_core.ai_risk_analyst.providers.local_rule_based import LocalRuleBasedAnalyst


class MockAnalyst(LocalRuleBasedAnalyst):
    """Same logic as rule-based analyst but fixed provider name for test assertions."""

    name = "mock"

    def analyze(self, bundle: AnalystEvidenceBundle) -> AIRecommendation:
        """Return analyze.

        Args:
            bundle: bundle supplied by the caller.

        Returns:
            The computed `AIRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        rec = super().analyze(bundle)
        return rec.model_copy(
            update={
                "provider": self.name,
                "audit_id": f"mock-audit-{bundle.incident_id}",
                "human_review_notes": "Mock analyst — deterministic test output.",
            }
        )
