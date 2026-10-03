"""Unified deterministic decision scoring (all domains)."""

from __future__ import annotations

from dataclasses import dataclass

from src.platform.models import DecisionOption, EvidenceItem, Hypothesis, NormalizedEvent

CONFIDENCE_BONUS_SCALE = 0.25
POLICY_PENALTIES = {
    "ALLOW_RESEARCH": 0.0,
    "PREVIEW_ONLY": 0.05,
    "BLOCK_AUTONOMOUS_ACTION": 0.15,
    "BLOCK_LOW_CONFIDENCE": 0.25,
    "BLOCK_DESTRUCTIVE_ACTION": 0.4,
}


@dataclass
class RankedDecision:
    """Represent ranked decision data used by the toolkit.

    Attributes:
        decision: Field or variant describing decision evidence or state.
        benefit: Field or variant describing benefit evidence or state.
        risk: Field or variant describing risk evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        confidence_bonus: Field or variant describing confidence bonus evidence or state.
        policy_penalty: Field or variant describing policy penalty evidence or state.
        final_score: Field or variant describing final score evidence or state.
        explanation: Field or variant describing explanation evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    decision: DecisionOption
    benefit: float
    risk: float
    confidence: float
    confidence_bonus: float
    policy_penalty: float
    final_score: float
    explanation: str


def score_decision(decision: DecisionOption, *, hypothesis_confidence: float) -> RankedDecision:
    """Score decision.

    Args:
        decision: The decision value supplied by the caller.
        hypothesis_confidence: The hypothesis confidence value supplied by the caller.

    Returns:
        The RankedDecision result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    bonus = round(hypothesis_confidence * CONFIDENCE_BONUS_SCALE, 4)
    penalty = POLICY_PENALTIES.get(decision.policy_status, 0.1)
    raw = decision.expected_benefit - decision.risk_score + bonus - penalty
    final = round(max(0.0, min(1.0, raw)), 4)
    explanation = (
        f"{decision.decision_id}: benefit={decision.expected_benefit:.2f} - risk={decision.risk_score:.2f} "
        f"+ bonus={bonus:.2f} - penalty={penalty:.2f} => {final:.2f}"
    )
    scored = decision.model_copy(
        update={
            "confidence": hypothesis_confidence,
            "final_score": final,
            "explanation": explanation,
        }
    )
    return RankedDecision(
        decision=scored,
        benefit=decision.expected_benefit,
        risk=decision.risk_score,
        confidence=hypothesis_confidence,
        confidence_bonus=bonus,
        policy_penalty=penalty,
        final_score=final,
        explanation=explanation,
    )


def rank_decisions(
    event: NormalizedEvent,
    ranked_hypotheses: list[Hypothesis],
    evidence: list[EvidenceItem],
    candidates: list[DecisionOption],
) -> list[RankedDecision]:
    """Rank decisions.

    Args:
        event: Evidence or domain record being processed.
        ranked_hypotheses: The ranked hypotheses value supplied by the caller.
        evidence: The evidence value supplied by the caller.
        candidates: The candidates value supplied by the caller.

    Returns:
        The list[RankedDecision] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    _ = event, evidence
    top_conf = ranked_hypotheses[0].confidence if ranked_hypotheses else 0.4
    scored = [score_decision(d, hypothesis_confidence=top_conf) for d in candidates]
    scored.sort(key=lambda r: (-r.final_score, r.decision.decision_id))
    return scored
