"""LLM-safe diagnosis-to-text rendering from structured evidence only."""

from __future__ import annotations

from platform_core.reasoning_models import ReasoningRun


def render_reasoning_summary(run: ReasoningRun) -> dict[str, str | list[str]]:
    """Render a human-readable summary without inventing facts.

    Args:
        run: Structured reasoning run.

    Returns:
        Dictionary suitable for UI or optional LLM translation. All content is derived from fields
        present in ``run``.
    """
    accepted = run.accepted_hypothesis or "unknown"
    state_path = (
        " -> ".join(run.evidence_tree.state_path)
        if run.evidence_tree.state_path
        else "no state transition"
    )
    proof_status = run.proof_result.status
    policy = run.policy_decision.outcome
    observed = ", ".join(run.evidence_tree.accepted_because[:8]) or "no accepted observations"
    rejected = [
        f"{item.get('hypothesis')}: {item.get('reason')}"
        for item in run.evidence_tree.rejected_alternatives
    ]
    short = (
        f"The endpoint reasoning engine selected {accepted}. State path: {state_path}. "
        f"Proof status is {proof_status}; policy outcome is {policy}."
    )
    evidence_summary = f"Accepted evidence: {observed}."
    if run.policy_decision.outcome == "ALLOW":
        safe_action = "Safe-tier action can proceed only through the existing confirmation and execution boundary."
    elif run.policy_decision.outcome == "PREVIEW":
        safe_action = "Keep remediation in preview mode until proof and typed confirmation requirements are met."
    else:
        safe_action = "Do not execute the requested remediation action."
    return {
        "short_diagnosis": short,
        "evidence_summary": evidence_summary,
        "rejected_alternatives": rejected,
        "proof_status": proof_status,
        "safe_next_action": safe_action,
        "limitations": run.limitations,
    }
