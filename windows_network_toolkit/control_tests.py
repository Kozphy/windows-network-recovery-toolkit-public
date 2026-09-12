"""Endpoint proxy control tests — PASS/FAIL/PARTIAL/NOT_TESTED from evidence.

Module responsibility:
    Evaluate six mature proxy controls from collected state, health audit, owner, and
    reverter diagnosis. Map incident classes to relevant control IDs for explainability.

System placement:
    Called by ``analytics_pipeline``, ``latest_evidence_report``, and CLI ``control-test``
    paths. Complements (does not replace) ``src/platform_core/risk/control_test.py`` for
    fixture case studies.

Key invariants:
    * Read-only — ``SAFE_REMEDIATION_POLICY`` asserts toolkit defaults, does not mutate host.
    * Outcomes: PASS, FAIL, PARTIAL, NOT_TESTED only.
    * Listener/process attribution documented as correlation-only in ``limitations``.

Decision intent:
    Answer whether proxy health, path contrast, alignment, reverter pattern, and safe
    remediation posture support or contradict the classified incident.

Audit Notes:
    * FAIL on reverter does not authorize process kill — recommendation cites Sysmon/Procmon.
    * PARTIAL on owner verification means writer proof unavailable (T4 not met).
    * Recovery: re-run ``proxy-health`` and ``proxy-owner`` elevated; enable E13 telemetry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

WRITER_LIMITATION = "Likely process / correlation only; registry writer proof unavailable."

# Incident class → primary control IDs exercised by map_control_tests_from_incident.
INCIDENT_CONTROL_MAP: dict[str, list[str]] = {
    "DEAD_PROXY_CONFIG": [
        "WININET_LOCALHOST_PROXY_HEALTH",
        "DIRECT_VS_PROXY_PATH_COMPARISON",
        "WININET_PROXY_OWNER_VERIFICATION",
    ],
    "LOCAL_PROXY_ACTIVE": [
        "WININET_LOCALHOST_PROXY_HEALTH",
        "WININET_PROXY_OWNER_VERIFICATION",
        "DIRECT_VS_PROXY_PATH_COMPARISON",
    ],
    "REVERTER_SUSPECTED": ["PROXY_REVERTER_DETECTION", "SAFE_REMEDIATION_POLICY"],
    "PROXY_FLAPPING": ["PROXY_REVERTER_DETECTION"],
    "WININET_WINHTTP_MISMATCH": ["WININET_WINHTTP_ALIGNMENT"],
    "DIRECT_ONLY_WORKS": ["DIRECT_VS_PROXY_PATH_COMPARISON"],
    "BOTH_DIRECT_AND_PROXY_FAIL": ["DIRECT_VS_PROXY_PATH_COMPARISON"],
    "NO_PROXY": ["SAFE_REMEDIATION_POLICY"],
    "UNKNOWN_LOCAL_PROXY": [
        "WININET_PROXY_OWNER_VERIFICATION",
        "WININET_LOCALHOST_PROXY_HEALTH",
    ],
}


def controls_for_incident_class(incident_class: str) -> list[str]:
    """Return control IDs relevant to an incident class for filtering and API catalog.

    Args:
        incident_class: Primary classification label (e.g. ``DEAD_PROXY_CONFIG``).

    Returns:
        List of ``control_id`` strings; defaults to health + safe remediation policy
        when class is not in ``INCIDENT_CONTROL_MAP``.
    """
    return list(
        INCIDENT_CONTROL_MAP.get(
            incident_class,
            [
                "WININET_LOCALHOST_PROXY_HEALTH",
                "SAFE_REMEDIATION_POLICY",
            ],
        )
    )


class ControlTestOutcome(StrEnum):
    """Mature control test result labels for endpoint proxy controls."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_TESTED = "NOT_TESTED"


@dataclass
class EndpointControlTestResult:
    """One control test evaluation with evidence and governance limitations.

    Attributes:
        control_id: Stable identifier (e.g. ``WININET_LOCALHOST_PROXY_HEALTH``).
        control_objective: Human-readable control statement.
        test_result: PASS, FAIL, PARTIAL, or NOT_TESTED.
        risk: Ordinal triage band for the finding (LOW/MEDIUM/HIGH).
        evidence: Supporting observation strings.
        limitations: Correlation and proof caveats.
        recommendation: Suggested next step — preview-only remediation by default.
    """

    control_id: str
    control_objective: str
    test_result: str
    risk: str
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return asdict(self)


def _health_status(health_audit: dict[str, Any] | None) -> str:
    if not health_audit:
        return ""
    return str((health_audit.get("health") or {}).get("proxy_status") or "")


def _test_localhost_proxy_health(
    *,
    state: dict[str, Any],
    health_audit: dict[str, Any] | None,
) -> EndpointControlTestResult:
    control_id = "WININET_LOCALHOST_PROXY_HEALTH"
    objective = "Localhost WinINET proxy must forward external HTTPS when enabled."
    parsed = (health_audit or {}).get("wininet", {}).get("parsed_proxy_server") or {}
    enabled = bool(state.get("wininet_proxy_enabled"))
    if not enabled or not parsed.get("is_localhost_proxy"):
        return EndpointControlTestResult(
            control_id=control_id,
            control_objective=objective,
            test_result=ControlTestOutcome.NOT_TESTED.value,
            risk="LOW",
            evidence=["WinINET localhost proxy not enabled — health control not applicable"],
            recommendation="No action unless proxy is later enabled toward localhost.",
        )
    status = _health_status(health_audit)
    evidence = list(health_audit.get("evidence") or [])[:4]
    if status in ("HEALTHY_LOCALHOST_PROXY", "BOTH_DIRECT_AND_PROXY_WORK", "PROXY_ONLY_WORKS"):
        result = ControlTestOutcome.PASS.value
        risk = "LOW"
        rec = "Continue monitoring; document expected dev tooling if applicable."
    elif status in ("DEAD_LOCALHOST_PROXY", "DIRECT_ONLY_WORKS"):
        result = ControlTestOutcome.FAIL.value
        risk = "HIGH"
        rec = "Preview proxy-disable with typed confirmation; verify listener before apply."
    elif status in ("LISTENER_NOT_PROXY", "PROXY_FORWARDING_FAILED"):
        result = ControlTestOutcome.FAIL.value
        risk = "HIGH"
        rec = "Investigate process on port; do not assume listener is a valid proxy."
    elif status == "BOTH_DIRECT_AND_PROXY_FAIL":
        result = ControlTestOutcome.FAIL.value
        risk = "HIGH"
        rec = "Broader network path investigation before proxy-specific remediation."
    else:
        result = ControlTestOutcome.PARTIAL.value
        risk = "MEDIUM"
        rec = "Re-run proxy-health with network access or fixture inject for full proof."
    return EndpointControlTestResult(
        control_id=control_id,
        control_objective=objective,
        test_result=result,
        risk=risk,
        evidence=evidence or [f"proxy_status={status}"],
        limitations=list(health_audit.get("limitations") or []) if health_audit else [],
        recommendation=rec,
    )


def _test_proxy_owner(
    *,
    state: dict[str, Any],
    owner: dict[str, Any] | None,
    health_audit: dict[str, Any] | None,
) -> EndpointControlTestResult:
    control_id = "WININET_PROXY_OWNER_VERIFICATION"
    objective = "Proxy registry changes should have a known and attributable owner."
    if not state.get("wininet_proxy_enabled"):
        return EndpointControlTestResult(
            control_id=control_id,
            control_objective=objective,
            test_result=ControlTestOutcome.NOT_TESTED.value,
            risk="LOW",
            evidence=["Proxy disabled"],
            recommendation="Enable proxy-watch when investigating drift.",
        )
    evidence: list[str] = []
    if state.get("wininet_proxy_server"):
        evidence.append(f"ProxyServer: {state.get('wininet_proxy_server')}")
    proc = (owner or {}).get("process") if isinstance((owner or {}).get("process"), dict) else None
    if proc and proc.get("name"):
        evidence.append(f"{proc.get('name')} was listening on port {(owner or {}).get('localhost_port')}")
        result = ControlTestOutcome.PARTIAL.value
        risk = "HIGH"
        rec = "Enable Sysmon Event ID 13 or collect Procmon registry trace."
    elif (owner or {}).get("listener_found"):
        result = ControlTestOutcome.PARTIAL.value
        risk = "MEDIUM"
        rec = "Listener found but process metadata incomplete — re-run proxy-owner elevated."
    else:
        result = ControlTestOutcome.FAIL.value
        risk = "HIGH"
        rec = "No listener owner — treat as dead proxy risk; collect writer attribution."
    limitations = [WRITER_LIMITATION, "Port ownership is correlation, not registry writer proof."]
    return EndpointControlTestResult(
        control_id=control_id,
        control_objective=objective,
        test_result=result,
        risk=risk,
        evidence=evidence,
        limitations=limitations,
        recommendation=rec,
    )


def _test_reverter_detection(reverter: dict[str, Any] | None) -> EndpointControlTestResult:
    control_id = "PROXY_REVERTER_DETECTION"
    objective = "Detect proxy settings returning after disable without operator confirmation."
    if not reverter or not reverter.get("status") or reverter.get("status") == "NONE":
        return EndpointControlTestResult(
            control_id=control_id,
            control_objective=objective,
            test_result=ControlTestOutcome.PASS.value,
            risk="LOW",
            evidence=["No reverter or flapping pattern in timeline window"],
            limitations=[WRITER_LIMITATION],
            recommendation="Continue proxy-watch during remediation windows.",
        )
    status = str(reverter.get("status"))
    if status in ("REVERTER_SUSPECTED", "PROXY_FLAPPING", "REPEATED_LOCALHOST_PROXY_PORTS"):
        result = ControlTestOutcome.FAIL.value
        risk = "HIGH"
    elif status == "STALE_PROXY_AFTER_PROCESS_EXIT":
        result = ControlTestOutcome.FAIL.value
        risk = "HIGH"
    else:
        result = ControlTestOutcome.PARTIAL.value
        risk = "MEDIUM"
    return EndpointControlTestResult(
        control_id=control_id,
        control_objective=objective,
        test_result=result,
        risk=risk,
        evidence=list(reverter.get("evidence") or []),
        limitations=list(reverter.get("limitations") or [WRITER_LIMITATION]),
        recommendation="Correlate with Sysmon registry writes; do not kill processes automatically.",
    )


def _test_direct_vs_proxy(health_audit: dict[str, Any] | None) -> EndpointControlTestResult:
    control_id = "DIRECT_VS_PROXY_PATH_COMPARISON"
    objective = "Compare direct HTTPS path with WinINET localhost proxy path."
    if not health_audit:
        return EndpointControlTestResult(
            control_id=control_id,
            control_objective=objective,
            test_result=ControlTestOutcome.NOT_TESTED.value,
            risk="LOW",
            evidence=["No health audit available"],
            recommendation="Run proxy-health before path comparison control.",
        )
    health = health_audit.get("health") or {}
    direct_ok = bool(health.get("direct_probe_ok"))
    proxy_ok = bool(health.get("proxy_probe_ok"))
    status = _health_status(health_audit)
    evidence = [
        f"direct_probe_ok={direct_ok}",
        f"proxy_probe_ok={proxy_ok}",
        f"proxy_status={status}",
    ]
    if direct_ok and proxy_ok:
        result, risk = ControlTestOutcome.PASS.value, "LOW"
        rec = "Both paths work — audit whether WinINET routing is intended."
    elif direct_ok and not proxy_ok:
        result, risk = ControlTestOutcome.FAIL.value, "HIGH"
        rec = "Browser likely broken via proxy — preview disable after human review."
    elif proxy_ok and not direct_ok:
        result, risk = ControlTestOutcome.PARTIAL.value, "MEDIUM"
        rec = "Proxy path works without direct — check VPN/tunnel dependency."
    else:
        result, risk = ControlTestOutcome.FAIL.value, "HIGH"
        rec = "Neither path succeeded — investigate DNS/TLS/firewall before proxy fix."
    return EndpointControlTestResult(
        control_id=control_id,
        control_objective=objective,
        test_result=result,
        risk=risk,
        evidence=evidence,
        limitations=list(health_audit.get("limitations") or []),
        recommendation=rec,
    )


def _test_safe_remediation_policy() -> EndpointControlTestResult:
    return EndpointControlTestResult(
        control_id="SAFE_REMEDIATION_POLICY",
        control_objective="Destructive remediation must remain preview-only or require typed confirmation.",
        test_result=ControlTestOutcome.PASS.value,
        risk="LOW",
        evidence=[
            "proxy-health and proxy-watch are read-only",
            "proxy-disable defaults to dry-run",
            "No automatic process kill or registry mutation in health pipeline",
        ],
        limitations=["Operator may still run gated commands manually"],
        recommendation="Use proxy-disable --dry-run true before any live apply.",
    )


def _test_wininet_winhttp_alignment(state: dict[str, Any]) -> EndpointControlTestResult:
    control_id = "WININET_WINHTTP_ALIGNMENT"
    objective = "WinINET and WinHTTP proxy configuration should align for predictable browser behavior."
    enabled = bool(state.get("wininet_proxy_enabled"))
    winhttp_direct = bool(state.get("winhttp_direct_access", True))
    if not enabled:
        return EndpointControlTestResult(
            control_id=control_id,
            control_objective=objective,
            test_result=ControlTestOutcome.PASS.value,
            risk="LOW",
            evidence=["WinINET proxy disabled"],
            recommendation="No alignment action required.",
        )
    if enabled and winhttp_direct:
        return EndpointControlTestResult(
            control_id=control_id,
            control_objective=objective,
            test_result=ControlTestOutcome.FAIL.value,
            risk="MEDIUM",
            evidence=[
                "WinINET proxy enabled",
                "WinHTTP reports direct access (no proxy server)",
            ],
            recommendation="Run diagnose --proof; reconcile WinINET vs WinHTTP with change management.",
        )
    return EndpointControlTestResult(
        control_id=control_id,
        control_objective=objective,
        test_result=ControlTestOutcome.PASS.value,
        risk="LOW",
        evidence=["WinINET and WinHTTP both indicate proxied or aligned configuration"],
        recommendation="Document expected corporate proxy policy.",
    )


def run_endpoint_control_tests(
    *,
    proxy_state: dict[str, Any],
    health_audit: dict[str, Any] | None = None,
    owner: dict[str, Any] | None = None,
    reverter_diagnosis: dict[str, Any] | None = None,
    timeline: list[dict[str, Any]] | None = None,
) -> list[EndpointControlTestResult]:
    """Generate six endpoint proxy control test results from collected evidence.

    Args:
        proxy_state: WinINET/WinHTTP state dict from ``proxy_state`` or evidence events.
        health_audit: Output shape from ``proxy_health`` / ``run_proxy_health_for_state``.
        owner: Listener owner dict from ``proxy_owner``.
        reverter_diagnosis: Reverter analysis dict from ``proxy_watch_diagnosis``.
        timeline: Reserved for future timeline-enriched controls (currently unused).

    Returns:
        List of six ``EndpointControlTestResult`` in stable order.

    Side effects:
        None.

    Audit Notes:
        ``SAFE_REMEDIATION_POLICY`` documents toolkit defaults; does not enforce policy at runtime.
    """
    _ = timeline  # reserved for future timeline-enriched controls
    return [
        _test_localhost_proxy_health(state=proxy_state, health_audit=health_audit),
        _test_proxy_owner(state=proxy_state, owner=owner, health_audit=health_audit),
        _test_reverter_detection(reverter_diagnosis),
        _test_direct_vs_proxy(health_audit),
        _test_safe_remediation_policy(),
        _test_wininet_winhttp_alignment(proxy_state),
    ]


def control_tests_to_dict(tests: list[EndpointControlTestResult]) -> list[dict[str, Any]]:
    """Serialize endpoint control test results to dictionaries.

    Args:
        tests: Control test result objects to serialize.

    Returns:
        List of JSON-compatible dictionaries.

    Side effects:
        None."""
    return [t.to_dict() for t in tests]


def map_control_tests_from_incident(
    incident: Any,
    events: list[Any],
) -> list[EndpointControlTestResult]:
    """Map one incident and its evidence events to refined control test results.

    Args:
        incident: ``IncidentRecord`` from ``incident_classifier``.
        events: ``EvidenceEvent`` list sharing the incident time window.

    Returns:
        Six control results with outcomes refined by ``incident.incident_class``.

    Raises:
        TypeError: When ``incident`` is not an ``IncidentRecord``.

    Audit Notes:
        Refinement may upgrade FAIL/PASS based on class — audit raw health evidence separately.
    """
    from windows_network_toolkit.evidence_schema import EvidenceEvent
    from windows_network_toolkit.incident_classifier import IncidentRecord

    if not isinstance(incident, IncidentRecord):
        raise TypeError("incident must be IncidentRecord")

    state_ev = next((e for e in reversed(events) if getattr(e, "evidence_type", None) == "proxy_state"), None)
    listener_ev = next((e for e in reversed(events) if getattr(e, "evidence_type", None) == "listener_state"), None)
    probe_ev = next((e for e in reversed(events) if getattr(e, "evidence_type", None) == "probe_result"), None)

    proxy_state = (state_ev.raw_snapshot if state_ev else {}) or {}
    if state_ev and isinstance(state_ev, EvidenceEvent):
        proxy_state = {**proxy_state, **state_ev.normalized_fields}

    health_audit = None
    if probe_ev and isinstance(probe_ev, EvidenceEvent):
        health_audit = {
            "health": probe_ev.normalized_fields,
            "evidence": [probe_ev.evidence_summary],
            "limitations": probe_ev.limitations,
            "wininet": {"parsed_proxy_server": {"is_localhost_proxy": bool(proxy_state.get("localhost_port"))}},
        }

    owner = listener_ev.raw_snapshot if listener_ev else None
    reverter = {
        "status": incident.incident_class if incident.incident_class in (
            "REVERTER_SUSPECTED",
            "PROXY_FLAPPING",
            "STALE_PROXY_AFTER_PROCESS_EXIT",
        ) else "NONE",
        "evidence": incident.supporting_evidence,
        "limitations": incident.limitations,
    }

    tests = run_endpoint_control_tests(
        proxy_state=proxy_state,
        health_audit=health_audit,
        owner=owner,
        reverter_diagnosis=reverter,
    )

    # Refine mapping from incident class per analytics spec
    refined: list[EndpointControlTestResult] = []
    for test in tests:
        result = test.test_result
        risk = test.risk
        evidence = list(test.evidence)
        recommendation = test.recommendation

        if test.control_id == "WININET_LOCALHOST_PROXY_HEALTH":
            if incident.incident_class == "DEAD_PROXY_CONFIG":
                result = ControlTestOutcome.FAIL.value
                risk = "HIGH"
            elif incident.incident_class in ("BOTH_DIRECT_AND_PROXY_WORK", "LOCAL_PROXY_ACTIVE", "PROXY_ONLY_WORKS"):
                result = ControlTestOutcome.PASS.value
        elif test.control_id == "WININET_PROXY_OWNER_VERIFICATION":
            if incident.incident_class in ("LOCAL_PROXY_ACTIVE", "UNKNOWN_LOCAL_PROXY", "BOTH_DIRECT_AND_PROXY_WORK"):
                has_writer = any(getattr(e, "evidence_tier", "") == "T4_WRITER_PROOF" for e in events)
                result = ControlTestOutcome.PASS.value if has_writer else ControlTestOutcome.PARTIAL.value
                risk = "HIGH" if result == ControlTestOutcome.PARTIAL.value else "LOW"
        elif test.control_id == "DIRECT_VS_PROXY_PATH_COMPARISON":
            if probe_ev is None:
                result = ControlTestOutcome.NOT_TESTED.value
            elif incident.incident_class in ("DIRECT_ONLY_WORKS", "BOTH_DIRECT_AND_PROXY_FAIL"):
                result = ControlTestOutcome.FAIL.value
            elif incident.incident_class in ("BOTH_DIRECT_AND_PROXY_WORK", "PROXY_ONLY_WORKS"):
                result = ControlTestOutcome.PASS.value
            else:
                result = ControlTestOutcome.PARTIAL.value
        elif test.control_id == "PROXY_REVERTER_DETECTION":
            if incident.incident_class in ("REVERTER_SUSPECTED", "PROXY_FLAPPING"):
                result = ControlTestOutcome.FAIL.value
                risk = "HIGH"
                evidence.append(incident.human_interpretation)
        elif test.control_id == "WININET_WINHTTP_ALIGNMENT":
            if incident.incident_class == "WININET_WINHTTP_MISMATCH":
                result = ControlTestOutcome.FAIL.value
                risk = "MEDIUM"

        refined.append(
            EndpointControlTestResult(
                control_id=test.control_id,
                control_objective=test.control_objective,
                test_result=result,
                risk=risk,
                evidence=evidence,
                limitations=test.limitations,
                recommendation=recommendation,
            )
        )
    return refined
