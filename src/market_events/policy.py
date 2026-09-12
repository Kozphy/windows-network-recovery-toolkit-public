"""Research policy guardrails — no trade execution, confidence and source gates."""

from __future__ import annotations

from .models import MarketEvent, ResearchPolicyStatus, SignalScore


def evaluate_research_policy(
    event: MarketEvent,
    *,
    request_execution: bool = False,
) -> ResearchPolicyStatus:
    """Evaluate research policy.
    
    Args:
        event: Evidence or domain record being processed.
        request_execution: The request execution value supplied by the caller.
    
    Returns:
        The ResearchPolicyStatus result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    if request_execution:
        return ResearchPolicyStatus.BLOCK_TRADE_EXECUTION
    if not (event.source or "").strip():
        return ResearchPolicyStatus.PREVIEW_ONLY
    if event.confidence < 0.4:
        return ResearchPolicyStatus.BLOCK_LOW_CONFIDENCE
    return ResearchPolicyStatus.ALLOW_RESEARCH


def apply_policy_to_score(score: SignalScore, status: ResearchPolicyStatus) -> SignalScore:
    """Apply policy to score.
    
    Args:
        score: The score value supplied by the caller.
        status: The status value supplied by the caller.
    
    Returns:
        The SignalScore result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    notes = list(score.risk_notes)
    if status == ResearchPolicyStatus.BLOCK_TRADE_EXECUTION:
        notes.append("Trade execution requests are always blocked in research mode.")
    elif status == ResearchPolicyStatus.PREVIEW_ONLY:
        notes.append("Missing or empty source — preview-only research signal.")
    elif status == ResearchPolicyStatus.BLOCK_LOW_CONFIDENCE:
        notes.append("Confidence below 0.4 — low-confidence research gate.")
    return score.model_copy(update={"policy_status": status, "risk_notes": notes})
