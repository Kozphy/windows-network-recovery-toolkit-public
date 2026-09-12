"""Failure scenario registry for endpoint event/state reasoning."""

from __future__ import annotations

from typing import Any

from platform_core.reasoning_models import EndpointEvent, FailureScenario, Observation
from platform_core.state_machine import event_category

TRUE_VALUES = {True, "true", "yes", "ok", "success", "succeeded", "enabled", "1"}


def _is_true(value: Any) -> bool:
    """Return whether an observation value should be treated as present/true."""
    if isinstance(value, str):
        return value.strip().lower() in TRUE_VALUES
    return value in TRUE_VALUES


def observation_signal_map(observations: list[Observation]) -> dict[str, Observation]:
    """Return the latest observation per signal name.

    Args:
        observations: Raw or normalized observations.

    Returns:
        Mapping from signal name to latest observation in input order.
    """
    signals: dict[str, Observation] = {}
    for obs in observations:
        signals[obs.signal_name] = obs
    return signals


def normalize_signals(observations: list[Observation]) -> dict[str, Any]:
    """Normalize observations into a simple replayable signal dictionary."""
    out: dict[str, Any] = {}
    for obs in observations:
        out[obs.signal_name] = (
            obs.normalized_value if obs.normalized_value is not None else obs.value
        )
    return out


def browser_proxy_path_regression() -> FailureScenario:
    """Return the default browser/proxy path regression scenario."""
    return FailureScenario(
        id="browser_proxy_path_regression",
        name="Browser proxy path regression",
        description=(
            "Browser and developer-tool HTTPS traffic is routed through a changed or broken local "
            "proxy while lower network layers remain healthy."
        ),
        states=[
            "healthy_browser_path",
            "proxy_drift_detected",
            "browser_path_failure_suspected",
            "proxy_path_failure_confirmed",
            "remediation_preview_ready",
            "resolved",
            "unresolved",
        ],
        events=[
            "wininet_proxy_changed",
            "localhost_proxy_detected",
            "browser_https_failed",
            "dns_ok",
            "tcp443_ok",
            "proxy_bypass_succeeded",
            "proxied_path_failed",
            "policy_preview_allowed",
        ],
        rules=[
            {
                "id": "proxy_drift",
                "requires_any": [
                    "wininet_proxy_changed",
                    "wininet_proxy_enabled",
                    "localhost_proxy_detected",
                ],
                "from_state": "healthy_browser_path",
                "to_state": "proxy_drift_detected",
            },
            {
                "id": "browser_path_suspected",
                "requires_all": [
                    "ping_ok",
                    "dns_ok",
                    "tcp443_ok",
                    "browser_https_failed",
                    "wininet_proxy_enabled",
                ],
                "from_state": "proxy_drift_detected",
                "to_state": "browser_path_failure_suspected",
            },
            {
                "id": "proxy_path_confirmed",
                "requires_all": ["proxy_bypass_succeeded", "proxied_path_failed"],
                "from_state": "browser_path_failure_suspected",
                "to_state": "proxy_path_failure_confirmed",
            },
            {
                "id": "preview_ready",
                "requires_all": ["policy_preview_allowed"],
                "from_state": "proxy_path_failure_confirmed",
                "to_state": "remediation_preview_ready",
            },
        ],
        alternative_hypotheses=[
            "total_network_outage",
            "dns_only_failure",
            "tcp_blocked",
            "upstream_isp_issue",
            "certificate_tls_issue",
        ],
        limitations=[
            "Listener/process correlation does not prove registry writer identity.",
            "Registry writer proof requires Sysmon/EventLog/Procmon-style telemetry.",
        ],
        recommended_next_steps=[
            "Run a proxy bypass contrast proof before changing registry values.",
            "Preserve proxy and process attribution evidence before remediation.",
        ],
    )


def default_failure_scenarios() -> dict[str, FailureScenario]:
    """Return all built-in failure scenarios keyed by ID."""
    scenario = browser_proxy_path_regression()
    alternatives = {
        "total_network_outage": FailureScenario(
            id="total_network_outage",
            name="Total network outage",
            description="L3/L4 connectivity is broadly unavailable.",
            states=["unknown", "network_outage_suspected", "rejected"],
            events=["ping_failed", "dns_failed", "tcp443_failed"],
        ),
        "dns_only_failure": FailureScenario(
            id="dns_only_failure",
            name="DNS-only failure",
            description="DNS resolution fails while raw network transport may still work.",
            states=["unknown", "dns_failure_suspected", "rejected"],
            events=["dns_failed", "ping_ok"],
        ),
        "tcp_blocked": FailureScenario(
            id="tcp_blocked",
            name="TCP 443 blocked",
            description="HTTPS transport is blocked below the browser/proxy layer.",
            states=["unknown", "tcp_block_suspected", "rejected"],
            events=["tcp443_failed"],
        ),
        "upstream_isp_issue": FailureScenario(
            id="upstream_isp_issue",
            name="Upstream ISP issue",
            description="External network path appears degraded beyond the endpoint.",
            states=["unknown", "upstream_issue_suspected", "rejected"],
            events=["ping_failed", "dns_failed", "tcp443_failed"],
        ),
        "certificate_tls_issue": FailureScenario(
            id="certificate_tls_issue",
            name="Certificate or TLS issue",
            description="HTTPS fails due to certificate or TLS validation, not proxy path drift.",
            states=["unknown", "tls_issue_suspected", "rejected"],
            events=["tls_certificate_error", "browser_https_failed"],
        ),
    }
    return {scenario.id: scenario, **alternatives}


def detect_endpoint_events(observations: list[Observation]) -> list[EndpointEvent]:
    """Convert true-valued observations into endpoint events.

    Args:
        observations: Raw observations from collectors or replay.

    Returns:
        Endpoint events preserving source observation IDs.
    """
    events: list[EndpointEvent] = []
    for obs in observations:
        if not _is_true(obs.normalized_value if obs.normalized_value is not None else obs.value):
            continue
        severity = (
            "medium"
            if obs.signal_name in {"browser_https_failed", "proxied_path_failed"}
            else "info"
        )
        if obs.signal_name in {
            "wininet_proxy_changed",
            "localhost_proxy_detected",
            "wininet_proxy_enabled",
        }:
            severity = "low"
        events.append(
            EndpointEvent(
                source=obs.source,
                event_type=obs.signal_name,
                category=event_category(obs.signal_name),
                severity=severity,  # type: ignore[arg-type]
                confidence=obs.confidence,
                observation_ids=[obs.id],
                details={"value": obs.value},
                limitations=list(obs.limitations),
                recommended_next_steps=list(obs.recommended_next_steps),
            )
        )
    return events


def event_types(events: list[EndpointEvent]) -> set[str]:
    """Return event type set from detected events."""
    return {event.event_type for event in events}
