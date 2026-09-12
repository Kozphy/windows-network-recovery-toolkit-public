"""Canonical endpoint reliability state machine (NORMAL → … → RECOVERING).

Scenario-specific states (e.g. ``proxy_drift_detected``) remain in
:class:`~platform_core.reasoning_models.StateTransition` for explainability.
This module projects those paths onto the platform-wide canonical enum and
applies explicit transition rules for ranking, policy, and audit replay.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso
from platform_core.reasoning_models import (
    EndpointEvent,
    StateTransition,
    new_id,
)

CanonicalState = Literal["NORMAL", "SUSPICIOUS", "DEGRADED", "BROKEN", "RECOVERING"]

CANONICAL_STATES: tuple[CanonicalState, ...] = (
    "NORMAL",
    "SUSPICIOUS",
    "DEGRADED",
    "BROKEN",
    "RECOVERING",
)

SCENARIO_TO_CANONICAL: dict[str, CanonicalState] = {
    "healthy_browser_path": "NORMAL",
    "proxy_drift_detected": "SUSPICIOUS",
    "browser_path_failure_suspected": "DEGRADED",
    "proxy_path_failure_confirmed": "BROKEN",
    "remediation_preview_ready": "BROKEN",
    "resolved": "RECOVERING",
    "unresolved": "BROKEN",
}

CANONICAL_TRANSITION_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "canonical_proxy_drift",
        "from_state": "NORMAL",
        "to_state": "SUSPICIOUS",
        "trigger_events": {
            "wininet_proxy_changed",
            "wininet_proxy_enabled",
            "localhost_proxy_detected",
        },
        "confidence": 0.72,
    },
    {
        "rule_id": "canonical_path_degraded",
        "from_state": "SUSPICIOUS",
        "to_state": "DEGRADED",
        "trigger_events": {
            "ping_ok",
            "dns_ok",
            "tcp443_ok",
            "browser_https_failed",
            "wininet_proxy_enabled",
        },
        "confidence": 0.84,
    },
    {
        "rule_id": "canonical_path_broken",
        "from_state": "DEGRADED",
        "to_state": "BROKEN",
        "trigger_events": {"proxy_bypass_succeeded", "proxied_path_failed"},
        "confidence": 0.92,
    },
    {
        "rule_id": "canonical_recovering",
        "from_state": "BROKEN",
        "to_state": "RECOVERING",
        "trigger_signals": {"endpoint_health_restored", "proxy_restored"},
        "confidence": 0.88,
    },
    {
        "rule_id": "canonical_restored",
        "from_state": "RECOVERING",
        "to_state": "NORMAL",
        "trigger_signals": {"browser_https_ok", "wininet_proxy_disabled"},
        "confidence": 0.90,
    },
)


def map_scenario_state(scenario_state: str) -> CanonicalState:
    """Map a scenario-specific state label to the canonical enum."""
    return SCENARIO_TO_CANONICAL.get(scenario_state, "SUSPICIOUS")


def event_category(event_type: str) -> str:
    """Classify an endpoint event for correlation and dashboards."""
    if event_type.endswith("_ok"):
        return "connectivity_positive"
    if event_type.endswith("_failed") or event_type.endswith("_failure"):
        return "connectivity_failure"
    if "proxy" in event_type:
        return "proxy"
    if event_type.startswith("browser_"):
        return "browser"
    if event_type.startswith("dns_") or event_type.startswith("tcp"):
        return "network_transport"
    if event_type.startswith("policy_"):
        return "policy"
    return "signal"


class CanonicalStateTransition(BaseModel):
    """Explicit transition on the canonical state machine."""

    id: str = Field(default_factory=lambda: new_id("ctrans"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "state_machine"
    from_state: CanonicalState
    to_state: CanonicalState
    rule_id: str
    scenario_rule_id: str = ""
    event_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict)


def _event_ids_for_types(required: set[str], events: list[EndpointEvent]) -> list[str]:
    return [event.id for event in events if event.event_type in required]


def _has_signal(signals: dict[str, Any], name: str) -> bool:
    value = signals.get(name)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return bool(value)


def infer_canonical_transitions(
    scenario_transitions: list[StateTransition],
    *,
    events: list[EndpointEvent],
    signals: dict[str, Any] | None = None,
) -> list[CanonicalStateTransition]:
    """Derive canonical transitions from scenario transitions and explicit rules."""
    signals = signals or {}
    observed = {event.event_type for event in events}
    canonical: list[CanonicalStateTransition] = []
    current: CanonicalState = "NORMAL"

    for rule in CANONICAL_TRANSITION_RULES:
        trigger_events = rule.get("trigger_events")
        trigger_signals = rule.get("trigger_signals")
        if trigger_events and not set(trigger_events).issubset(observed):
            continue
        if trigger_signals and not all(_has_signal(signals, name) for name in trigger_signals):
            continue
        from_state = rule["from_state"]
        to_state = rule["to_state"]
        if current != from_state:
            continue
        event_ids = (
            _event_ids_for_types(set(trigger_events), events) if trigger_events else []
        )
        canonical.append(
            CanonicalStateTransition(
                from_state=from_state,
                to_state=to_state,
                rule_id=rule["rule_id"],
                confidence=float(rule.get("confidence") or 0.0),
                event_ids=event_ids,
                details={"trigger": "explicit_rule"},
            )
        )
        current = to_state

    for transition in scenario_transitions:
        mapped_from = map_scenario_state(transition.from_state)
        mapped_to = map_scenario_state(transition.to_state)
        if mapped_to == current:
            continue
        if mapped_from != current and canonical:
            continue
        canonical.append(
            CanonicalStateTransition(
                from_state=current,
                to_state=mapped_to,
                rule_id=f"canonical_map_{transition.rule_id or 'scenario'}",
                scenario_rule_id=transition.rule_id,
                confidence=transition.confidence,
                event_ids=list(transition.event_ids),
                details={
                    "scenario_from": transition.from_state,
                    "scenario_to": transition.to_state,
                    "trigger": "scenario_projection",
                },
            )
        )
        current = mapped_to

    return _dedupe_canonical_transitions(canonical)


def _dedupe_canonical_transitions(
    transitions: list[CanonicalStateTransition],
) -> list[CanonicalStateTransition]:
    """Keep the first transition for each (from_state, to_state, rule_id) triple."""
    seen: set[tuple[str, str, str]] = set()
    out: list[CanonicalStateTransition] = []
    for item in transitions:
        key = (item.from_state, item.to_state, item.rule_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def canonical_state_path(transitions: list[CanonicalStateTransition]) -> list[CanonicalState]:
    """Build ordered canonical path from transition list."""
    if not transitions:
        return ["NORMAL"]
    path: list[CanonicalState] = [transitions[0].from_state]
    for item in transitions:
        if path[-1] != item.to_state:
            path.append(item.to_state)
    return path
