"""Blameless postmortem generation from incident timeline + RCA."""

from __future__ import annotations

from platform_core import storage
from platform_core.reliability.models import PlatformDecisionRecord

from .event_store import DomainEventStore, append_domain_event
from .models import PostmortemDocument
from .mttr import _delta_seconds
from .projector import rebuild_incident
from .rca import build_rca_report
from .timeline import reconstruct_timeline, timeline_to_markdown

POSTMORTEM_DIR = "postmortems"


def generate_postmortem(
    incident_id: str,
    *,
    decision: PlatformDecisionRecord | None = None,
    store: DomainEventStore | None = None,
    persist: bool = True,
    actor: str = "system",
) -> PostmortemDocument:
    """Generate structured postmortem — linked to canonical event log."""
    st = store or DomainEventStore()
    proj = rebuild_incident(incident_id, store=st)
    rca = build_rca_report(incident_id, decision=decision, projection=proj)
    timeline = reconstruct_timeline(incident_id, store=st)
    timeline_md = timeline_to_markdown(timeline)

    mttd = _delta_seconds(proj.detected_at, proj.acknowledged_at or proj.investigation_started_at)
    mtti = _delta_seconds(proj.detected_at, proj.root_cause_identified_at)
    mttr = _delta_seconds(proj.detected_at, proj.resolved_at)
    duration = mttr

    impact = (
        f"Endpoint `{proj.endpoint_id}` — severity **{proj.severity}**. "
        f"State path: {' → '.join(proj.state_path) if proj.state_path else 'not computed'}."
    )

    what_well: list[str] = []
    what_wrong: list[str] = []

    if proj.investigation_started_at:
        what_well.append("Investigation workflow was initiated and event-sourced.")
    if decision and decision.audit_signature:
        what_well.append("Decision record is HMAC-signed for tamper detection.")
    if rca.confidence_tier in ("proven", "contrast_tested"):
        what_well.append(f"Root cause tier reached: {rca.confidence_tier}.")
    else:
        what_wrong.append("Root cause remains observational — proof tier not established.")

    if decision and decision.policy_outcome == "PREVIEW":
        what_well.append("Policy correctly held PREVIEW (no unsafe auto-remediation).")
    if not proj.resolved_at:
        what_wrong.append("Incident not resolved — MTTR incomplete.")

    action_items: list[dict[str, str]] = []
    for i, action in enumerate(rca.recommended_actions[:5], start=1):
        action_items.append(
            {"owner": "SRE", "action": action, "priority": "P1" if i == 1 else "P2"}
        )

    chain_lines = [f"- {step}" for step in rca.causal_chain] or ["- (none)"]
    root_cause_md = "\n".join(
        [
            f"**Statement:** {rca.root_cause_statement}",
            f"**Confidence tier:** {rca.confidence_tier}",
            "",
            "**Causal chain:**",
            *chain_lines,
            "",
            "**Limitations:**",
            *[f"- {lim}" for lim in rca.limitations],
        ]
    )

    doc = PostmortemDocument(
        incident_id=incident_id,
        title=proj.title or f"Incident {incident_id}",
        severity=proj.severity,
        duration_seconds=duration,
        mttd_seconds=mttd,
        mttr_seconds=mttr,
        mtti_seconds=mtti,
        summary=(
            f"Postmortem for incident `{incident_id}` on endpoint `{proj.endpoint_id}`. "
            f"Phase at generation: {proj.phase.value}. "
            "This document is generated from append-only domain events — replayable and auditable."
        ),
        timeline_markdown=timeline_md,
        root_cause_markdown=root_cause_md,
        impact=impact,
        what_went_well=what_well,
        what_went_wrong=what_wrong,
        action_items=action_items,
        limitations=rca.limitations,
        correlation_id=incident_id,
    )

    if persist:
        out_dir = storage.platform_data_dir() / POSTMORTEM_DIR
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / f"{doc.postmortem_id}.md"
        md_path.write_text(doc.to_markdown(), encoding="utf-8")
        storage.append_jsonl(
            storage.platform_data_dir() / "sre_postmortems.jsonl",
            doc.model_dump(mode="json"),
        )
        append_domain_event(
            aggregate_id=incident_id,
            aggregate_type="incident",
            event_type="postmortem.generated",
            correlation_id=incident_id,
            payload={"postmortem_id": doc.postmortem_id, "path": str(md_path)},
            actor=actor,
            store=st,
        )

    return doc
