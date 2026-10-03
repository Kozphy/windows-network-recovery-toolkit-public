"""Optional OpenAI-backed analyst — falls back when API key is missing."""

from __future__ import annotations

import json
import os
from typing import Any

from src.platform_core.ai_risk_analyst.models import AIRecommendation, AnalystEvidenceBundle
from src.platform_core.ai_risk_analyst.providers.base import AnalystProvider
from src.platform_core.ai_risk_analyst.providers.local_rule_based import LocalRuleBasedAnalyst


class OpenAIAnalyst(AnalystProvider):
    """Represent the open aianalyst type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    name = "openai"

    def __init__(self, *, model: str = "gpt-4o-mini", api_key: str | None = None) -> None:
        """Initialize the open aianalyst instance.

        Args:
            model: model supplied by the caller.
            api_key: api key supplied by the caller.

        Returns:
            None.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._fallback = LocalRuleBasedAnalyst()

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
        if not self._api_key:
            rec = self._fallback.analyze(bundle)
            return rec.model_copy(
                update={
                    "provider": "local_rule_based",
                    "governance_notes": [
                        *rec.governance_notes,
                        "OPENAI_API_KEY not set; used rule-based fallback.",
                    ],
                }
            )

        try:
            import httpx
        except ImportError:
            rec = self._fallback.analyze(bundle)
            return rec.model_copy(
                update={
                    "governance_notes": [
                        *rec.governance_notes,
                        "httpx unavailable; rule-based fallback.",
                    ],
                }
            )

        prompt = self._build_prompt(bundle)
        try:
            response = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a technology risk analyst. Output JSON only. "
                                "Never recommend killing processes or autonomous remediation."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                },
                timeout=30.0,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            data = json.loads(content)
            return self._parse_response(data, bundle)
        except Exception:
            rec = self._fallback.analyze(bundle)
            return rec.model_copy(
                update={
                    "governance_notes": [
                        *rec.governance_notes,
                        "OpenAI call failed; used rule-based fallback.",
                    ],
                }
            )

    def _build_prompt(self, bundle: AnalystEvidenceBundle) -> str:
        payload = bundle.model_dump(mode="json")
        return (
            "Analyze endpoint reliability evidence. Return JSON with: incident_summary, "
            "likely_hypothesis, missing_evidence, risk_level, confidence_level, "
            "recommended_action, human_review_notes, assumptions, uncertainty, "
            f"alternative_explanations. Evidence: {json.dumps(payload, ensure_ascii=False)}"
        )

    def _parse_response(
        self, data: dict[str, Any], bundle: AnalystEvidenceBundle
    ) -> AIRecommendation:
        base = self._fallback.analyze(bundle)
        return base.model_copy(
            update={
                "provider": self.name,
                "incident_summary": str(data.get("incident_summary", base.incident_summary)),
                "likely_hypothesis": str(data.get("likely_hypothesis", base.likely_hypothesis)),
                "missing_evidence": list(data.get("missing_evidence", base.missing_evidence)),
                "risk_level": data.get("risk_level", base.risk_level),
                "confidence_level": data.get("confidence_level", base.confidence_level),
                "recommended_action": str(data.get("recommended_action", base.recommended_action)),
                "human_review_notes": str(data.get("human_review_notes", base.human_review_notes)),
                "assumptions": list(data.get("assumptions", base.assumptions)),
                "uncertainty": str(data.get("uncertainty", base.uncertainty)),
                "alternative_explanations": list(
                    data.get("alternative_explanations", base.alternative_explanations)
                ),
            }
        )
