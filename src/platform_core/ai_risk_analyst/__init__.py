"""AI-assisted risk analysis — advisory only; no autonomous remediation."""

from __future__ import annotations

from src.platform_core.ai_risk_analyst.explanation_guardrails import (
    ExplanationValidationResult,
    sanitize_explanation_text,
    validate_explanation_text,
)

from .guardrails import apply_guardrails, recommendation_passes_safety
from .models import (
    AIRecommendation,
    AnalystAuditEntry,
    AnalystEvidenceBundle,
    DecisionRecord,
    HumanReviewRequired,
    RiskAnalysisResult,
    RiskHypothesis,
)
from .providers import LocalRuleBasedAnalyst, MockAnalyst

__all__ = [
    "AIRecommendation",
    "AnalystAuditEntry",
    "AnalystEvidenceBundle",
    "DecisionRecord",
    "HumanReviewRequired",
    "LocalRuleBasedAnalyst",
    "MockAnalyst",
    "RiskAnalysisResult",
    "RiskHypothesis",
    "apply_guardrails",
    "recommendation_passes_safety",
    "ExplanationValidationResult",
    "sanitize_explanation_text",
    "validate_explanation_text",
]
