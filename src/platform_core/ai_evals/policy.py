"""Policy gates for AI eval outcomes.

Maps detected failure labels and signals to a single ``EvalPolicyGate`` decision
(e.g. ALLOW, PREVIEW, REQUIRE_HUMAN_REVIEW, BLOCK) with rationale and recommendations.

Operates on deterministic eval results only; no live model inference.
"""

from __future__ import annotations

from .failure_taxonomy import EvalPolicyGate, FailureLabel
from .schemas import EvalCase, EvalPolicyDecision, EvalResult, FailureSignal

_GATE_PRIORITY: dict[EvalPolicyGate, int] = {
    EvalPolicyGate.ALLOW: 0,
    EvalPolicyGate.PREVIEW: 1,
    EvalPolicyGate.INSUFFICIENT_EVIDENCE: 2,
    EvalPolicyGate.REQUIRE_HUMAN_REVIEW: 3,
    EvalPolicyGate.BLOCK: 4,
}


def normalize_eval_policy(gate: str) -> EvalPolicyGate:
    """Normalize eval policy.

    Args:
        gate: gate supplied by the caller.

    Returns:
        The computed `EvalPolicyGate` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    key = str(gate or "").strip().upper()
    mapping = {
        "ALLOW": EvalPolicyGate.ALLOW,
        "PREVIEW": EvalPolicyGate.PREVIEW,
        "PREVIEW_ONLY": EvalPolicyGate.PREVIEW,
        "REQUIRE_HUMAN_REVIEW": EvalPolicyGate.REQUIRE_HUMAN_REVIEW,
        "REQUIRE_HUMAN_APPROVAL": EvalPolicyGate.REQUIRE_HUMAN_REVIEW,
        "HUMAN_REVIEW": EvalPolicyGate.REQUIRE_HUMAN_REVIEW,
        "BLOCK": EvalPolicyGate.BLOCK,
        "INSUFFICIENT_EVIDENCE": EvalPolicyGate.INSUFFICIENT_EVIDENCE,
    }
    return mapping.get(key, EvalPolicyGate.PREVIEW)


def _gate_for_label(label: FailureLabel, case: EvalCase) -> EvalPolicyGate:
    if label == FailureLabel.CORRECT:
        return EvalPolicyGate.ALLOW
    if label == FailureLabel.FORMAT_VIOLATION:
        return EvalPolicyGate.PREVIEW
    if label == FailureLabel.UNSUPPORTED_CLAIM:
        if case.severity == "high":
            return EvalPolicyGate.BLOCK
        return EvalPolicyGate.REQUIRE_HUMAN_REVIEW
    if label == FailureLabel.HALLUCINATION_RISK:
        if case.severity == "high":
            return EvalPolicyGate.BLOCK
        return EvalPolicyGate.REQUIRE_HUMAN_REVIEW
    if label == FailureLabel.SAFETY_REVIEW_REQUIRED:
        return EvalPolicyGate.BLOCK
    if label == FailureLabel.INSUFFICIENT_EVIDENCE:
        return EvalPolicyGate.INSUFFICIENT_EVIDENCE
    if label in {FailureLabel.RETRIEVAL_MISS, FailureLabel.REFUSAL_UNEXPECTED}:
        return EvalPolicyGate.REQUIRE_HUMAN_REVIEW
    if label == FailureLabel.LATENCY_OR_COST_REGRESSION:
        return EvalPolicyGate.PREVIEW
    return EvalPolicyGate.PREVIEW


def evaluate_eval_policy(
    case: EvalCase,
    *,
    failure_labels: list[FailureLabel],
    failure_signals: list[FailureSignal],
) -> EvalPolicyDecision:
    """Map failure labels to a single eval policy gate."""
    if not failure_labels or failure_labels == [FailureLabel.CORRECT]:
        return EvalPolicyDecision(
            gate=EvalPolicyGate.ALLOW,
            rationale="Eval checks passed with sufficient evidence markers.",
            requires_human_review=False,
            recommendation="Continue monitoring; re-run eval on model updates.",
        )

    gates = [
        _gate_for_label(label, case) for label in failure_labels if label != FailureLabel.CORRECT
    ]
    if not gates:
        gates = [EvalPolicyGate.PREVIEW]

    gate = max(gates, key=lambda g: _GATE_PRIORITY[g])
    blocked = [s.detail for s in failure_signals if s.severity == "high"]
    requires_review = gate in {
        EvalPolicyGate.REQUIRE_HUMAN_REVIEW,
        EvalPolicyGate.BLOCK,
        EvalPolicyGate.INSUFFICIENT_EVIDENCE,
    }

    rationale_parts = [
        f"Primary gate {gate.value} from labels: {', '.join(label.value for label in failure_labels)}."
    ]
    recommendation = _recommendation_for_gate(gate)

    return EvalPolicyDecision(
        gate=gate,
        rationale=" ".join(rationale_parts),
        requires_human_review=requires_review,
        blocked_reasons=blocked,
        recommendation=recommendation,
    )


def _recommendation_for_gate(gate: EvalPolicyGate) -> str:
    mapping = {
        EvalPolicyGate.ALLOW: "No blocking issues — optional spot-check before partner release.",
        EvalPolicyGate.PREVIEW: "Review output format or cost profile before promoting prompt.",
        EvalPolicyGate.REQUIRE_HUMAN_REVIEW: "Route case to human reviewer before using output in production.",
        EvalPolicyGate.BLOCK: "Do not deploy this prompt/output path without remediation.",
        EvalPolicyGate.INSUFFICIENT_EVIDENCE: "Collect citations or grounding evidence before approval.",
    }
    note = mapping.get(gate, "Review eval limitations before action.")
    return f"{note} (Recommendation is not execution authority.)"


def attach_policy_to_result(case: EvalCase, result: EvalResult) -> EvalResult:
    """Attach policy to result.

    Args:
        case: case supplied by the caller.
        result: result supplied by the caller.

    Returns:
        The computed `EvalResult` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    policy = evaluate_eval_policy(
        case,
        failure_labels=result.failure_labels,
        failure_signals=result.failure_signals,
    )
    result.policy_decision = policy
    result.recommendation = policy.recommendation
    return result
