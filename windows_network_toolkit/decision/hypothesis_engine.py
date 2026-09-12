"""Incident type evaluation from normalised signal maps.

Module responsibility:
    Consume a flat signal dict, delegate scenario ranking to
    ``proxy_reasoning.scenarios.rank_hypotheses``, map the top-ranked
    scenario case ID to an ``IncidentType``, compute ordinal confidence, and
    produce a fully populated ``DecisionResult``.

System placement:
    The core decision layer, invoked by ``windows_network_toolkit.pipeline``
    and the ``/platform/diagnose`` API endpoint.  Imports from
    ``proxy_reasoning`` (deterministic scenario ranking) and from
    ``windows_network_toolkit.evidence.confidence_score`` (ordinal scoring).

Key invariants:
    * Signal normalisation is case-insensitive and lower-cased; the original
      values are not modified.
    * ``requires_confirmation=True`` on any action that mutates system state.
    * The fallback path (no ranked hypotheses) always produces a valid
      ``DecisionResult`` — the system degrades gracefully to ``NO_PROXY`` or
      ``UNKNOWN_LOCAL_PROXY`` rather than raising.
    * Incident type is a hypothesis, not a verdict: classification ≠
      accusation.  ``human_review_required`` is set for high-uncertainty or
      high-risk incident types.

Side effects:
    None — pure evaluation; no I/O, no registry, no network access.

Failure modes:
    ``rank_hypotheses`` exceptions propagate to the caller.  Signal type
    errors (non-string keys) are normalised silently via ``str(k).lower()``.

Audit Notes:
    ``DecisionResult.evidence_refs`` carries the supporting signal names from
    the top-ranked hypothesis; these should be correlated against the
    ``EvidenceBundle.events`` list in the audit record.
"""

from __future__ import annotations

import uuid
from typing import Any

from proxy_reasoning.constants import (
    CASE_BROWSER_PROXY_PATH_ISSUE,
    CASE_LOCALHOST_PROXY_LISTENER,
    CASE_WININET_PROXY_DRIFT,
)
from proxy_reasoning.models import ProxySignal
from proxy_reasoning.scenarios import rank_hypotheses
from windows_network_toolkit.evidence.confidence_score import explain_confidence, ordinal_confidence

from .decision_model import DecisionResult, IncidentType
from .risk_classifier import classify_risk


def _truthy(value: Any) -> bool:
    """Coerce a heterogeneous signal value to a boolean truth test.

    Handles booleans, numbers, and the string literals commonly produced by
    Windows registry readers and collector payloads.

    Args:
        value: The raw signal value from a collector or fixture.

    Returns:
        ``True`` when the value represents an active / enabled / present state.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "ok", "success", "enabled", "on"}
    return bool(value)


def _signals_map(signals: dict[str, Any]) -> dict[str, Any]:
    """Normalise a signal dict to lower-case string keys.

    Args:
        signals: Raw signal dict from a collector or fixture.

    Returns:
        A new dict with all keys lower-cased; values are unchanged.
    """
    return {str(k).lower(): v for k, v in signals.items()}


def _has(sm: dict[str, Any], *names: str) -> bool:
    """Test whether any of ``names`` resolves to a truthy value in the signal map.

    Args:
        sm: Lower-cased signal map (from ``_signals_map``).
        *names: Signal key names to test; both as-supplied and lower-cased
            variants are checked.

    Returns:
        ``True`` when at least one name maps to a truthy value.
    """
    for name in names:
        if _truthy(sm.get(name.lower())) or _truthy(sm.get(name)):
            return True
    return False


def _map_case_to_incident(case_id: str, sm: dict[str, Any]) -> IncidentType:
    """Map a ``proxy_reasoning`` case ID to an ``IncidentType`` using signal context.

    Some case IDs resolve to different incident types depending on whether
    complementary signals are present (e.g. ``CASE_LOCALHOST_PROXY_LISTENER``
    resolves to ``WRITER_AND_LISTENER_MATCH`` only when both writer and
    listener signals are truthy).

    Args:
        case_id: Case identifier returned by ``rank_hypotheses``.
        sm: Lower-cased signal map (used to apply sub-case refinements).

    Returns:
        The most specific ``IncidentType`` supported by the observed signals.
    """
    if case_id == CASE_WININET_PROXY_DRIFT:
        if _has(sm, "proxy_bypass_succeeded", "direct_path_succeeds", "direct_path_success"):
            return IncidentType.PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS
        return IncidentType.WININET_PROXY_DRIFT
    if case_id == CASE_LOCALHOST_PROXY_LISTENER:
        if _has(sm, "registry_writer_observed", "sysmon_event_13", "writer_process"):
            if _has(sm, "listener_on_proxy_port", "listener_process_name"):
                return IncidentType.WRITER_AND_LISTENER_MATCH
            return IncidentType.REGISTRY_REWRITER_OBSERVED
        if _has(sm, "classification", "UNKNOWN_LOCAL_PROXY"):
            return IncidentType.UNKNOWN_LOCAL_PROXY
        if _has(sm, "classification", "SUSPICIOUS_PROXY"):
            return IncidentType.SUSPICIOUS_PROXY
        if _has(sm, "classification", "POSSIBLE_MITM_RISK"):
            return IncidentType.POSSIBLE_MITM_RISK
        return IncidentType.UNKNOWN_LOCAL_PROXY
    if case_id == CASE_BROWSER_PROXY_PATH_ISSUE:
        return IncidentType.DNS_OK_BROWSER_FAIL
    if _has(sm, "proxy_enable", "wininet_proxy_enabled") and not _truthy(sm.get("proxy_enable")):
        return IncidentType.NO_PROXY
    if _has(sm, "classification", "KNOWN_DEV_PROXY"):
        return IncidentType.KNOWN_DEV_PROXY
    if _has(sm, "classification", "KNOWN_SECURITY_TOOL"):
        return IncidentType.KNOWN_SECURITY_TOOL
    return IncidentType.UNKNOWN_LOCAL_PROXY


def _recommended_action(incident: IncidentType) -> tuple[str, bool]:
    """Return the recommended operator action and confirmation requirement for an incident type.

    Args:
        incident: The resolved ``IncidentType``.

    Returns:
        A ``(action_token, requires_confirmation)`` tuple.  ``action_token``
        is a string constant (e.g. ``"DISABLE_WININET_PROXY_WITH_CONFIRMATION"``);
        ``requires_confirmation`` is ``True`` whenever system state could be
        mutated.
    """
    mapping = {
        IncidentType.NO_PROXY: ("OBSERVE_ONLY", False),
        IncidentType.KNOWN_DEV_PROXY: ("OBSERVE_ONLY", False),
        IncidentType.KNOWN_SECURITY_TOOL: ("OBSERVE_ONLY", False),
        IncidentType.UNKNOWN_LOCAL_PROXY: ("INVESTIGATE_LISTENER", True),
        IncidentType.SUSPICIOUS_PROXY: ("HUMAN_REVIEW", True),
        IncidentType.POSSIBLE_MITM_RISK: ("HUMAN_REVIEW", True),
        IncidentType.WININET_PROXY_DRIFT: ("DISABLE_WININET_PROXY_WITH_CONFIRMATION", True),
        IncidentType.PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS: (
            "DISABLE_WININET_PROXY_WITH_CONFIRMATION",
            True,
        ),
        IncidentType.REGISTRY_REWRITER_OBSERVED: ("COLLECT_WRITER_PROOF", True),
        IncidentType.WRITER_AND_LISTENER_MATCH: ("STOP_LISTENER_WITH_CONFIRMATION", True),
        IncidentType.DNS_OK_BROWSER_FAIL: ("PROXY_PATH_DIAGNOSTIC", True),
    }
    return mapping.get(incident, ("OBSERVE_ONLY", True))


def evaluate_incident(
    signals: dict[str, Any],
    *,
    incident_id: str,
    evidence_refs: list[str] | None = None,
) -> DecisionResult:
    """Evaluate a signal map and produce a ``DecisionResult``.

    Delegates scenario ranking to ``proxy_reasoning.scenarios.rank_hypotheses``
    then selects the highest-ranked hypothesis as the incident type.  When no
    hypothesis is ranked, a safe fallback is applied based on the presence of
    ``proxy_enable`` / ``wininet_proxy_enabled`` signals.

    Confidence is boosted (up to 0.85) for ``WININET_PROXY_DRIFT`` and
    ``PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS`` incidents when both a browser path
    failure and a successful direct path are observed — the combination
    provides stronger evidence for disabling the proxy setting.

    Args:
        signals: Flat signal dict from a collector run or fixture.  Keys may
            be mixed case; they are normalised internally.
        incident_id: Identifier of the evidence bundle this evaluation belongs
            to.
        evidence_refs: Optional list of evidence IDs or signal names to
            include as ``evidence_refs`` in the result.

    Returns:
        A fully populated ``DecisionResult``.  The result always has
        ``requires_confirmation=True`` for any mutating action.

    Note:
        The returned ``incident_type`` is the top-ranked hypothesis given the
        supplied signals.  It represents an analytic classification, not
        forensic proof.
    """
    sm = _signals_map(signals)
    proxy_signals = [ProxySignal(name=k, value=v) for k, v in signals.items()]
    ranked = rank_hypotheses(proxy_signals)

    if ranked:
        top = ranked[0]
        incident_type = _map_case_to_incident(top.case_id, sm)
        confidence = ordinal_confidence(top.confidence_rank)
        if incident_type in {
            IncidentType.WININET_PROXY_DRIFT,
            IncidentType.PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS,
        }:
            if _has(sm, "browser_https_failed", "browser_path_fails") and _has(
                sm, "proxy_bypass_succeeded", "direct_path_succeeds", "direct_path_success"
            ):
                confidence = max(confidence, 0.85)
        reasoning = explain_confidence(top.confidence_rank, supporting=list(top.supporting_signals))
        refs = list(evidence_refs or []) + list(top.supporting_signals)
    else:
        if not _has(sm, "proxy_enable", "wininet_proxy_enabled"):
            incident_type = IncidentType.NO_PROXY
            confidence = 0.55
            reasoning = "No proxy enable signal observed; defaulting to NO_PROXY."
            refs = list(evidence_refs or [])
        elif _has(sm, "classification", "KNOWN_DEV_PROXY"):
            incident_type = IncidentType.KNOWN_DEV_PROXY
            confidence = 0.7
            reasoning = "Known dev proxy classification from signals."
            refs = list(evidence_refs or [])
        else:
            incident_type = IncidentType.UNKNOWN_LOCAL_PROXY
            confidence = 0.6
            reasoning = "Insufficient scenario match; unknown local proxy posture."
            refs = list(evidence_refs or [])

    action, requires_confirmation = _recommended_action(incident_type)
    risk = classify_risk(incident_type, confidence)
    human_review = incident_type in {
        IncidentType.SUSPICIOUS_PROXY,
        IncidentType.POSSIBLE_MITM_RISK,
        IncidentType.REGISTRY_REWRITER_OBSERVED,
    }

    return DecisionResult(
        decision_id=f"dec-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        incident_type=incident_type,
        confidence=confidence,
        risk_level=risk,
        recommended_action=action,
        requires_confirmation=requires_confirmation,
        reasoning=reasoning,
        evidence_refs=refs,
        human_review_required=human_review,
        metadata={"ranked_hypotheses": [h.case_id for h in ranked]},
    )
