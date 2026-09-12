"""Deterministic production state machine — replayable transitions."""

from __future__ import annotations

from typing import Any

from .models import NormalizedPlatformEvent, PlatformState, PlatformStateTransition

# Explicit transition rules: (from_state, rule_id, required_signals, to_state, confidence)
PLATFORM_TRANSITION_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "localhost_proxy_enabled",
        "from_state": PlatformState.NORMAL,
        "to_state": PlatformState.LOCAL_PROXY_ENABLED,
        "signals": {"wininet_proxy_enabled", "localhost_proxy_detected"},
        "confidence": 0.75,
    },
    {
        "rule_id": "proxy_path_failure",
        "from_state": PlatformState.LOCAL_PROXY_ENABLED,
        "to_state": PlatformState.PROXY_FAILURE,
        "signals": {"browser_https_failed", "wininet_proxy_enabled"},
        "confidence": 0.82,
    },
    {
        "rule_id": "bypass_success",
        "from_state": PlatformState.PROXY_FAILURE,
        "to_state": PlatformState.BYPASS_SUCCESS,
        "signals": {"proxy_bypass_succeeded", "proxied_path_failed"},
        "confidence": 0.90,
    },
    {
        "rule_id": "root_cause_identified",
        "from_state": PlatformState.BYPASS_SUCCESS,
        "to_state": PlatformState.ROOT_CAUSE_IDENTIFIED,
        "signals_any": {"proof_confirmed", "sysmon_registry_write"},
        "confidence": 0.92,
    },
    {
        "rule_id": "recovering",
        "from_state": PlatformState.BROKEN,
        "to_state": PlatformState.RECOVERING,
        "signals": {"proxy_disabled", "endpoint_health_restored"},
        "confidence": 0.85,
    },
    {
        "rule_id": "restored_normal",
        "from_state": PlatformState.RECOVERING,
        "to_state": PlatformState.NORMAL,
        "signals": {"browser_https_ok", "wininet_proxy_disabled"},
        "confidence": 0.88,
    },
)


def _signal_set(events: list[NormalizedPlatformEvent]) -> set[str]:
    out: set[str] = set()
    for ev in events:
        out.add(ev.signal_name)
        if ev.evidence_tier == "TIER_3_CAUSAL_PROOF":
            out.add("proof_confirmed")
        if ev.source_kind == "sysmon" and "proxy" in ev.signal_name.lower():
            out.add("sysmon_registry_write")
        if ev.signal_name == "proxy_enable" and ev.signal_value in (0, False, "0"):
            out.add("wininet_proxy_disabled")
            out.add("proxy_disabled")
        if ev.signal_name == "proxy_enable" and ev.signal_value in (1, True, "1"):
            out.add("wininet_proxy_enabled")
    return out


def transition_platform_state(
    events: list[NormalizedPlatformEvent],
    *,
    endpoint_id: str = "local",
    initial: PlatformState = PlatformState.NORMAL,
) -> tuple[list[PlatformStateTransition], list[PlatformState]]:
    """Apply explicit rules; return transitions and ordered state path."""
    observed = _signal_set(events)
    event_ids = [e.event_id for e in events]
    transitions: list[PlatformStateTransition] = []
    current = initial
    path: list[PlatformState] = [current]

    for rule in PLATFORM_TRANSITION_RULES:
        required = set(rule.get("signals") or ())
        required_any = set(rule.get("signals_any") or ())
        from_state = rule["from_state"]
        to_state = rule["to_state"]
        if current != from_state:
            continue
        if required and not required.issubset(observed):
            continue
        if required_any and not (required_any & observed):
            continue
        triggers = [eid for e in events if e.signal_name in (required | required_any) for eid in [e.event_id]]
        transitions.append(
            PlatformStateTransition(
                endpoint_id=endpoint_id,
                from_state=current.value,
                to_state=to_state.value,
                rule_id=rule["rule_id"],
                triggering_event_ids=triggers or event_ids[:3],
                confidence=float(rule.get("confidence") or 0.0),
            )
        )
        current = to_state
        if path[-1] != current:
            path.append(current)

    return transitions, path
