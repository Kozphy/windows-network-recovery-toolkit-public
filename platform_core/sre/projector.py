"""Deterministic read-model projections from domain events — replayable state rebuild."""

from __future__ import annotations

from .event_store import DomainEventStore
from .models import DomainEvent, IncidentPhase, IncidentProjection


class Projector:
    """Apply domain events to incident projection — pure, deterministic, no side effects."""

    @staticmethod
    def apply(event: DomainEvent, state: IncidentProjection) -> IncidentProjection:
        """Provide apply behavior for toolkit workflows.

        Args:
            event: Value supplied by the caller for event.
            state: Value supplied by the caller for state.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        state.event_count += 1
        state.last_sequence = event.sequence

        if event.event_type == "incident.detected":
            state.phase = IncidentPhase.DETECTED
            state.detected_at = event.timestamp_utc
            state.title = str(event.payload.get("title") or state.title or "Endpoint incident")
            state.severity = event.payload.get("severity") or state.severity  # type: ignore[assignment]
            state.endpoint_id = str(event.payload.get("endpoint_id") or state.endpoint_id)
            state.limitations = list(event.payload.get("limitations") or state.limitations)

        elif event.event_type == "incident.acknowledged":
            state.phase = IncidentPhase.ACKNOWLEDGED
            state.acknowledged_at = event.timestamp_utc

        elif event.event_type == "incident.investigation_started":
            state.phase = IncidentPhase.INVESTIGATING
            state.investigation_started_at = event.timestamp_utc

        elif event.event_type == "incident.hypothesis_ranked":
            state.accepted_hypothesis = str(
                event.payload.get("accepted_hypothesis") or state.accepted_hypothesis or ""
            )
            run_id = event.payload.get("run_id")
            if run_id and run_id not in state.decision_run_ids:
                state.decision_run_ids.append(str(run_id))
            state.state_path = list(event.payload.get("state_path") or state.state_path)
            for eid in event.payload.get("event_ids") or []:
                if eid not in state.evidence_event_ids:
                    state.evidence_event_ids.append(str(eid))

        elif event.event_type == "incident.root_cause_identified":
            state.phase = IncidentPhase.ROOT_CAUSE_IDENTIFIED
            state.root_cause_identified_at = event.timestamp_utc
            state.root_cause_summary = str(
                event.payload.get("root_cause_summary") or state.root_cause_summary or ""
            )
            state.accepted_hypothesis = str(
                event.payload.get("accepted_hypothesis") or state.accepted_hypothesis or ""
            )

        elif event.event_type == "incident.mitigation_attempted":
            state.phase = IncidentPhase.MITIGATING

        elif event.event_type == "incident.resolved":
            state.phase = IncidentPhase.RESOLVED
            state.resolved_at = event.timestamp_utc

        elif event.event_type == "incident.false_positive":
            state.phase = IncidentPhase.FALSE_POSITIVE
            state.resolved_at = event.timestamp_utc
            state.limitations.append("Classified false positive — root cause not established.")

        elif event.event_type == "decision.recorded":
            run_id = event.payload.get("run_id")
            if run_id and run_id not in state.decision_run_ids:
                state.decision_run_ids.append(str(run_id))

        return state

    @classmethod
    def fold(
        cls, events: list[DomainEvent], *, incident_id: str, endpoint_id: str = ""
    ) -> IncidentProjection:
        """Provide fold behavior for toolkit workflows.

        Args:
            events: Value supplied by the caller for events.
            incident_id: Value supplied by the caller for incident id.
            endpoint_id: Value supplied by the caller for endpoint id.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        state = IncidentProjection(incident_id=incident_id, endpoint_id=endpoint_id)
        for event in sorted(events, key=lambda e: e.sequence):
            state = cls.apply(event, state)
        return state


def rebuild_incident(
    incident_id: str,
    *,
    store: DomainEventStore | None = None,
) -> IncidentProjection:
    """Rebuild incident read model from canonical event log — time-travel debugging."""
    st = store or DomainEventStore()
    events = st.load_aggregate_events(incident_id)
    if not events:
        return IncidentProjection(incident_id=incident_id, endpoint_id="")
    endpoint_id = str(events[0].payload.get("endpoint_id") or "")
    return Projector.fold(events, incident_id=incident_id, endpoint_id=endpoint_id)


def list_incident_ids(*, store: DomainEventStore | None = None) -> list[str]:
    """Enumerate incident aggregate ids from canonical log."""
    st = store or DomainEventStore()
    seen: set[str] = set()
    for event in st.iter_events(limit=100_000):
        if event.aggregate_type == "incident" and event.aggregate_id not in seen:
            seen.add(event.aggregate_id)
    return sorted(seen)
