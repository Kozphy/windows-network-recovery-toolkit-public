"""Evidence-driven root cause analysis — correlation is not causation."""

from __future__ import annotations

from typing import Any

from platform_core.reliability.models import PlatformDecisionRecord

from .models import IncidentProjection, RCAReport
from .projector import rebuild_incident


def _tier_from_decision(record: PlatformDecisionRecord | None) -> str:
    if record is None:
        return "observation"
    limitations = " ".join(record.limitations).lower()
    if "proof" in limitations and "no proof" not in limitations:
        return "proven"
    graph = record.evidence_graph_summary or {}
    nodes = graph.get("nodes") or []
    for node in nodes:
        if isinstance(node, dict) and node.get("strength") == "proof":
            return "proven"
    if record.state_path and "ROOT_CAUSE_IDENTIFIED" in record.state_path:
        return "contrast_tested"
    return "correlated"


def build_rca_report(
    incident_id: str,
    *,
    decision: PlatformDecisionRecord | None = None,
    projection: IncidentProjection | None = None,
) -> RCAReport:
    """Build RCA from incident projection + optional decision record."""
    proj = projection or rebuild_incident(incident_id)

    limitations = list(proj.limitations)
    limitations.extend(
        [
            "RCA output is an investigative artifact, not a legal or security conviction.",
            "Observation != Proof; supporting edges in the evidence graph are weighted, not causal certainty.",
        ]
    )

    accepted = proj.accepted_hypothesis or (decision.accepted_hypothesis if decision else None)
    tier = _tier_from_decision(decision)
    if proj.root_cause_summary:
        root_cause = proj.root_cause_summary
    elif accepted:
        root_cause = f"Leading hypothesis: {accepted} (tier={tier})"
    else:
        root_cause = "Root cause not established — insufficient proof-tier evidence."

    supporting: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    causal_chain: list[str] = []

    if decision:
        ranking = decision.hypothesis_ranking or []
        if ranking:
            top = ranking[0]
            supporting.append(
                {
                    "hypothesis": top.get("label"),
                    "confidence": top.get("confidence"),
                    "signals": top.get("supporting_signals"),
                }
            )
            for alt in ranking[1:4]:
                rejected.append(
                    {
                        "hypothesis": alt.get("label"),
                        "confidence": alt.get("confidence"),
                        "reason": alt.get("rejected_reason") or "lower ordinal rank",
                    }
                )
        graph = decision.evidence_graph_summary or {}
        for node in (graph.get("nodes") or [])[:8]:
            if isinstance(node, dict):
                supporting.append(
                    {"kind": node.get("kind"), "label": node.get("label"), "strength": node.get("strength")}
                )
        for step in decision.state_path or []:
            causal_chain.append(f"Platform state: {step}")

    actions: list[str] = []
    if tier in ("observation", "correlated"):
        actions.append("Collect proof-tier telemetry (Sysmon registry writer, Procmon) before remediation.")
    if "LOCAL_PROXY_ENABLED" in proj.state_path:
        actions.append("Identify listener process and parent chain; verify against allowlist.")
    if decision and decision.policy_outcome == "PREVIEW":
        actions.append("Policy PREVIEW — no automated remediation; human confirmation required.")
    if not actions:
        actions.append("Document resolution steps in incident.resolve() event for MTTR accounting.")

    return RCAReport(
        incident_id=incident_id,
        root_cause_statement=root_cause,
        confidence_tier=tier,  # type: ignore[arg-type]
        accepted_hypothesis=accepted,
        supporting_evidence=supporting,
        rejected_hypotheses=rejected,
        causal_chain=causal_chain,
        limitations=limitations,
        recommended_actions=actions,
    )
