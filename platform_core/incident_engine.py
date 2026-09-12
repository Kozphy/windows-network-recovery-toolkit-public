"""Deterministic incident creation and transition rules."""

from __future__ import annotations

import uuid
from typing import Any

from platform_core.incident_model import IncidentRecord, IncidentSeverity, IncidentState
from platform_core.incident_store import append_incident_event, get_incident
from platform_core.models import utc_now_iso

VALID_TRANSITIONS: dict[IncidentState, set[IncidentState]] = {
    "OPEN": {"ACKNOWLEDGED", "MITIGATED", "RESOLVED", "FALSE_POSITIVE"},
    "ACKNOWLEDGED": {"MITIGATED", "RESOLVED", "FALSE_POSITIVE"},
    "MITIGATED": {"RESOLVED", "FALSE_POSITIVE"},
    "RESOLVED": set(),
    "FALSE_POSITIVE": set(),
}


def can_transition(from_state: IncidentState, to_state: IncidentState) -> bool:
    """Evaluate the can transition condition.

    Args:
        from_state: Value supplied by the caller for from state.
        to_state: Value supplied by the caller for to state.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    return to_state in VALID_TRANSITIONS.get(from_state, set())


def _signal_names(observations: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for obs in observations:
        name = str(obs.get("name") or obs.get("signal") or "")
        if name:
            names.add(name)
    return names


def evaluate_incident_candidate(
    *,
    endpoint_id: str,
    observations: list[dict[str, Any]],
    persistence_indicators: dict[str, Any] | None = None,
    proxy_reenabled_after_soak: bool = False,
    evidence_level: str = "inference",
) -> IncidentRecord | None:
    """Create incident only when rules match; weak evidence cannot be critical."""
    signals = _signal_names(observations)
    persistence = persistence_indicators or {}
    suspicious_persistence = bool(
        persistence.get("suspicious_startup") or persistence.get("run_key_hits")
    )

    browser_failed = "browser_https_failed" in signals or any("browser" in s for s in signals)
    proxy_enabled = "wininet_proxy_enabled" in signals or any("proxy_enabled" in s for s in signals)
    bypass_ok = "proxy_bypass_succeeded" in signals

    severity: IncidentSeverity = "low"
    title = ""
    limitations: list[str] = []

    if browser_failed and proxy_enabled and bypass_ok:
        severity = "medium"
        title = "Browser HTTPS failed with WinINET proxy enabled; bypass path succeeded"
    elif proxy_reenabled_after_soak:
        severity = "high"
        title = "Proxy re-enabled after remediation soak window"
    elif proxy_enabled and suspicious_persistence:
        severity = "high"
        title = "Unknown local proxy with suspicious persistence indicator"
    else:
        return None

    if evidence_level in ("observation", "inference") and severity == "critical":
        severity = "high"
        limitations.append("Weak evidence caps severity below critical.")

    if evidence_level == "observation":
        limitations.append("Incident created from observations only; proof not established.")

    incident_id = str(uuid.uuid4())
    record = IncidentRecord(
        incident_id=incident_id,
        endpoint_id=endpoint_id,
        title=title,
        state="OPEN",
        severity=severity,
        evidence_level=evidence_level,
        created_at=utc_now_iso(),
        updated_at=utc_now_iso(),
        signals=sorted(signals),
        limitations=limitations,
    )
    append_incident_event(record.model_dump(mode="json"))
    return record


def apply_transition(
    incident_id: str,
    *,
    new_state: IncidentState,
    actor: str = "platform_api",
) -> IncidentRecord:
    """Apply transition for toolkit workflows.

    Args:
        incident_id: Value supplied by the caller for incident id.
        new_state: Value supplied by the caller for new state.
        actor: Value supplied by the caller for actor.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    current = get_incident(incident_id)
    if not current:
        raise KeyError(f"incident not found: {incident_id}")
    from_state = str(current.get("state") or "OPEN")
    if not can_transition(from_state, new_state):  # type: ignore[arg-type]
        raise ValueError(f"invalid transition {from_state} -> {new_state}")
    from platform_core.incident_store import transition_incident

    return transition_incident(incident_id, new_state=new_state, actor=actor)
