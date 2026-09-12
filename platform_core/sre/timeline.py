"""Incident timeline reconstruction from canonical domain events."""

from __future__ import annotations

from .event_store import DomainEventStore
from .models import TimelineEntry

_EVENT_SUMMARIES: dict[str, str] = {
    "incident.detected": "Incident detected",
    "incident.acknowledged": "Incident acknowledged by operator",
    "incident.investigation_started": "Investigation started",
    "incident.hypothesis_ranked": "Hypothesis ranked (evidence-driven)",
    "incident.root_cause_identified": "Root cause identified (see limitations)",
    "incident.mitigation_attempted": "Mitigation attempted",
    "incident.resolved": "Incident resolved",
    "incident.false_positive": "Marked false positive",
    "telemetry.normalized": "Telemetry normalized",
    "state.transitioned": "State transition applied",
    "decision.recorded": "Decision recorded",
    "audit.signed": "Audit entry signed",
    "domain.circuit_opened": "Failure domain circuit OPENED",
    "domain.circuit_closed": "Failure domain circuit closed",
    "postmortem.generated": "Postmortem generated",
}


def _summarize(event_type: str, payload: dict) -> str:
    base = _EVENT_SUMMARIES.get(event_type, event_type)
    if event_type == "incident.hypothesis_ranked":
        hyp = payload.get("accepted_hypothesis") or "unknown"
        return f"{base}: {hyp}"
    if event_type == "incident.root_cause_identified":
        return f"{base}: {payload.get('root_cause_summary', '')[:120]}"
    if event_type == "incident.mitigation_attempted":
        return f"{base}: {payload.get('action')} → {payload.get('outcome')}"
    if event_type == "incident.resolved":
        return f"{base}: {payload.get('resolution', '')[:80]}"
    if event_type == "domain.circuit_opened":
        return f"{base} ({payload.get('domain')})"
    return base


def reconstruct_timeline(
    incident_id: str,
    *,
    store: DomainEventStore | None = None,
    include_correlated: bool = True,
) -> list[TimelineEntry]:
    """Rebuild chronological timeline for incident investigation."""
    st = store or DomainEventStore()
    entries: list[TimelineEntry] = []

    for event in st.iter_events(aggregate_id=incident_id, limit=50_000):
        entries.append(_to_entry(event))

    if include_correlated:
        for event in st.iter_events(correlation_id=incident_id, limit=50_000):
            if event.aggregate_id == incident_id:
                continue
            entries.append(_to_entry(event))

    entries.sort(key=lambda e: (e.timestamp_utc, e.sequence))
    return entries


def timeline_to_markdown(entries: list[TimelineEntry]) -> str:
    """Provide timeline to markdown behavior for toolkit workflows.

    Args:
        entries: Value supplied by the caller for entries.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    if not entries:
        return "_No timeline events recorded._\n"
    lines = ["| Time (UTC) | Seq | Event | Summary |", "| --- | --- | --- | --- |"]
    for e in entries:
        lines.append(f"| {e.timestamp_utc} | {e.sequence} | `{e.event_type}` | {e.summary} |")
    return "\n".join(lines) + "\n"


def _to_entry(event) -> TimelineEntry:  # type: ignore[no-untyped-def]
    excerpt = {
        k: event.payload[k]
        for k in list(event.payload.keys())[:6]
        if k in ("run_id", "action", "outcome", "severity", "policy_outcome", "domain")
    }
    return TimelineEntry(
        sequence=event.sequence,
        timestamp_utc=event.timestamp_utc,
        event_type=event.event_type,
        event_id=event.event_id,
        summary=_summarize(event.event_type, event.payload),
        failure_domain=event.failure_domain,
        causation_id=event.causation_id,
        payload_excerpt=excerpt,
    )
