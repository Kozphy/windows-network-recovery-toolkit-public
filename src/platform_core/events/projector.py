"""Read models projected from trisk domain events."""

from __future__ import annotations

from typing import Any

from src.platform_core.events.models import TriskDomainEvent
from src.platform_core.events.store import TriskEventStore, get_event_store


def project_evidence_timeline(
    aggregate_id: str,
    *,
    store: TriskEventStore | None = None,
) -> list[dict[str, Any]]:
    """Timeline entries for one evidence aggregate."""
    s = store or get_event_store()
    return [
        {
            "event_id": e.event_id,
            "event_type": e.event_type.value,
            "sequence": e.sequence,
            "timestamp_utc": e.timestamp_utc,
            "actor": e.actor,
            "payload": e.payload,
            "limitations": e.limitations,
        }
        for e in s.iter_events(aggregate_id=aggregate_id, limit=500)
    ]


def project_incident_summary(
    incident_aggregate_id: str,
    *,
    store: TriskEventStore | None = None,
) -> dict[str, Any]:
    """Return project incident summary.

    Args:
        incident_aggregate_id: incident aggregate id supplied by the caller.
        store: store supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        May read or write local platform records depending on inputs.
    """
    events = list((store or get_event_store()).iter_events(aggregate_id=incident_aggregate_id, limit=200))
    classifications = [e for e in events if e.event_type.value == "RiskClassified"]
    controls = [e for e in events if e.event_type.value == "ControlTestCompleted"]
    return {
        "aggregate_id": incident_aggregate_id,
        "event_count": len(events),
        "risk_events": len(classifications),
        "control_events": len(controls),
        "timeline": [
            {"event_type": e.event_type.value, "timestamp_utc": e.timestamp_utc, "payload": e.payload}
            for e in events
        ],
    }


def list_recent_events(
    *,
    limit: int = 50,
    offset: int = 0,
    store: TriskEventStore | None = None,
) -> list[TriskDomainEvent]:
    """List recent events.

    Args:
        limit: limit supplied by the caller.
        offset: offset supplied by the caller.
        store: store supplied by the caller.

    Returns:
        The computed `list[TriskDomainEvent]` value.

    Side effects:
        May read or write local platform records depending on inputs.
    """
    return (store or get_event_store()).list_events(limit=limit, offset=offset)
