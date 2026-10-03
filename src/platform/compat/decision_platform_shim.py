"""Shim: platform_core.decision_platform models → src.platform.models.

DEPRECATED — use ``src.platform`` directly.
"""

from __future__ import annotations

import warnings

from src.platform.models import DecisionOption, DecisionOutcome, EvidenceItem, NormalizedEvent


def warn_deprecated(caller: str) -> None:
    """Warn deprecated.

    Args:
        caller: The caller value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    warnings.warn(
        f"{caller} is deprecated; use src.platform instead.",
        DeprecationWarning,
        stacklevel=3,
    )


def event_from_observation(obs: dict, *, event_id: str, domain: str) -> NormalizedEvent:
    """Event from observation.

    Args:
        obs: The obs value supplied by the caller.
        event_id: The event id value supplied by the caller.
        domain: The domain value supplied by the caller.

    Returns:
        The NormalizedEvent result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    warn_deprecated("platform_core.decision_platform Observation mapping")
    return NormalizedEvent(
        event_id=event_id,
        domain=domain,  # type: ignore[arg-type]
        category=str(obs.get("signal", "observation")),
        title=str(obs.get("signal", "observation")),
        timestamp_utc=str(obs.get("timestamp_utc", "")),
        observations=[{"signal": obs.get("signal"), "value": obs.get("value")}],
        source=str(obs.get("source_ref", "")),
    )


def evidence_from_legacy(ev: dict, *, event_id: str) -> EvidenceItem:
    """Evidence from legacy.

    Args:
        ev: The ev value supplied by the caller.
        event_id: The event id value supplied by the caller.

    Returns:
        The EvidenceItem result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    warn_deprecated("platform_core.decision_platform Evidence")
    return EvidenceItem(
        evidence_id=str(ev.get("evidence_id", "")),
        event_id=event_id,
        type="observation",
        description=str(ev.get("label", ev.get("detail", ""))),
        confidence_delta=float(ev.get("weight", 0.5)),
        source=str(ev.get("domain", "")),
    )


def decision_from_legacy(dec: dict, *, event_id: str) -> DecisionOption:
    """Decision from legacy.

    Args:
        dec: The dec value supplied by the caller.
        event_id: The event id value supplied by the caller.

    Returns:
        The DecisionOption result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    warn_deprecated("platform_core.decision_platform Decision")
    return DecisionOption(
        decision_id=str(dec.get("decision_id", "")),
        event_id=event_id,
        title=str(dec.get("title", "")),
        expected_benefit=float(dec.get("benefit", 50)) / 100.0,
        risk_score=float(dec.get("risk", 15)) / 100.0,
        confidence=float(dec.get("confidence", 0.5)),
        final_score=float(dec.get("final_score", 0)) / 100.0,
    )


def outcome_from_legacy(oc: dict) -> DecisionOutcome:
    """Outcome from legacy.

    Args:
        oc: The oc value supplied by the caller.

    Returns:
        The DecisionOutcome result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    warn_deprecated("platform_core.decision_platform Outcome")
    return DecisionOutcome(
        outcome_id=str(oc.get("outcome_id", "")),
        decision_id=str(oc.get("decision_id", "")),
        success=bool(oc.get("success")),
        observed_result=str(oc.get("notes", "")),
    )
