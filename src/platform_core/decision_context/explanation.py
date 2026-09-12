"""Human-readable explanation from DecisionEnvelope — no stronger causal language than proof."""

from __future__ import annotations

from typing import Any

from src.platform_core.decision_context.models import DecisionEnvelope


def explain_decision_envelope(envelope: DecisionEnvelope) -> dict[str, Any]:
    """Structured explanation derived from the same envelope used for JSON output."""
    sh = envelope.stakeholder
    tm = envelope.timing
    lines = [
        f"Case: {envelope.case_id}",
        f"Policy decision: {envelope.policy_decision}",
        f"Coordination status: {envelope.coordination_status.value}",
    ]
    if sh:
        owner = sh.asset_owner.display_name if sh.asset_owner else "(unresolved)"
        lines.append(f"Asset owner role: {owner}")
        if sh.unresolved_fields:
            lines.append(f"Unresolved stakeholder fields: {', '.join(sh.unresolved_fields)}")
        lines.append(f"Stakeholder confidence: {sh.resolution_confidence}")
    if tm:
        lines.append(f"Timing decision: {tm.decision.value}")
        lines.append(f"Urgency: {tm.urgency.value}")
        lines.append(f"Timezone: {tm.timezone}")
        if tm.sla_due_utc:
            lines.append(f"SLA due (UTC): {tm.sla_due_utc}")
        if tm.evidence_expires_utc:
            lines.append(f"Evidence expires (UTC): {tm.evidence_expires_utc}")

    lines.append("")
    lines.append("Principles:")
    for p in envelope.limitations:
        lines.append(f"- {p}")

    return {
        "schema_version": envelope.schema_version,
        "case_id": envelope.case_id,
        "policy_decision": envelope.policy_decision,
        "coordination_status": envelope.coordination_status.value,
        "summary_lines": lines,
        "text": "\n".join(lines),
        "limitations": list(envelope.limitations),
        "non_claims": list(envelope.non_claims),
    }


def format_decision_text(envelope: DecisionEnvelope) -> str:
    """Format decision text.

    Args:
        envelope: envelope supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return str(explain_decision_envelope(envelope)["text"])
