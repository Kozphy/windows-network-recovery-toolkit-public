"""Incident classification from normalized analytics evidence events.

Module responsibility:
    Derive primary ``incident_class``, triage ``risk_level``, and policy recommendations from
    normalized ``EvidenceEvent`` bundles — without claiming malware or root cause.

System placement:
    Consumed by ``analytics_pipeline`` and indirectly by risk scoring and control test mapping.

Key invariants:
    * Every ``IncidentRecord`` includes ``limitations[]`` (standard + case-specific).
    * ``confidence`` is ordinal 0–1, not statistical probability.
    * Classification is not accusation — listener names are correlation only.

Decision intent:
    Triage endpoint proxy incidents for human review and control testing.

Audit Notes:
    * ``REVERTER_SUSPECTED`` requires timeline evidence — verify proxy-watch JSONL.
    * Recovery: collect additional probe_result events via ``proxy-health``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from windows_network_toolkit.evidence_schema import STANDARD_LIMITATIONS, EvidenceEvent

_DEV_TRUSTED = frozenset({"node.exe", "node", "python.exe", "python"})


@dataclass
class IncidentRecord:
    """Classified endpoint proxy incident for analytics and governance export.

    Attributes:
        incident_id: Stable hash id from ``make_incident_id``.
        timestamp_utc: Latest evidence timestamp (UTC ISO-8601).
        endpoint_id: Host identifier when present in evidence.
        incident_class: Primary classification label.
        risk_level: Triage band LOW/MEDIUM/HIGH/UNKNOWN (distinct from ``risk_scoring_engine``).
        confidence: Ordinal 0–1 strength of classification.
        supporting_evidence: Human-readable supporting lines.
        contradicting_evidence: Lines that weaken the classification.
        limitations: Governance caveats — always populated.
        recommended_policy_action: observe, preview, or escalate hint.
        human_interpretation: Narrative for auditors and operators.
    """

    incident_id: str
    timestamp_utc: str
    endpoint_id: str | None
    incident_class: str
    risk_level: str
    confidence: float
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    recommended_policy_action: str = "observe"
    human_interpretation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return asdict(self)


def make_incident_id(timestamp_utc: str, incident_class: str, endpoint_id: str | None) -> str:
    """Build deterministic incident id from classification inputs.

    Args:
        timestamp_utc: Latest evidence timestamp (UTC).
        incident_class: Primary incident class label.
        endpoint_id: Host identifier or None for local default.

    Returns:
        Stable ``INC-`` prefixed hex id.

    Side effects:
        None.
    """
    payload = json.dumps(
        {"ts": timestamp_utc, "class": incident_class, "endpoint": endpoint_id or "local"},
        sort_keys=True,
    )
    return "INC-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _latest_by_type(events: list[EvidenceEvent], evidence_type: str) -> EvidenceEvent | None:
    matches = [e for e in events if e.evidence_type == evidence_type]
    if not matches:
        return None
    return sorted(matches, key=lambda e: e.timestamp_utc)[-1]


def _bool_field(events: list[EvidenceEvent], evidence_type: str, field_name: str) -> bool | None:
    ev = _latest_by_type(events, evidence_type)
    if not ev:
        return None
    val = ev.normalized_fields.get(field_name)
    if val is None:
        return None
    return bool(val)


def _str_field(events: list[EvidenceEvent], evidence_type: str, field_name: str) -> str | None:
    ev = _latest_by_type(events, evidence_type)
    if not ev or ev.normalized_fields.get(field_name) is None:
        return None
    return str(ev.normalized_fields.get(field_name))


def classify_incident_from_events(
    events: list[EvidenceEvent],
    *,
    timestamp_utc: str | None = None,
    endpoint_id: str | None = None,
) -> IncidentRecord:
    """Classify one incident from a bundle of normalized evidence events.

    Args:
        events: Normalized evidence for one time window; may be empty.
        timestamp_utc: Override latest timestamp; inferred from events when None.
        endpoint_id: Override endpoint id; inferred from events when None.

    Returns:
        IncidentRecord with class, risk_level, confidence, and limitations.
        Empty events yield ``INSUFFICIENT_DATA`` with low confidence.

    Side effects:
        None.
    """
    if not events:
        ts = timestamp_utc or ""
        return IncidentRecord(
            incident_id=make_incident_id(ts, "INSUFFICIENT_DATA", endpoint_id),
            timestamp_utc=ts,
            endpoint_id=endpoint_id,
            incident_class="INSUFFICIENT_DATA",
            risk_level="UNKNOWN",
            confidence=0.2,
            limitations=list(STANDARD_LIMITATIONS) + ["No evidence events supplied."],
            human_interpretation="Insufficient evidence to classify endpoint proxy incident.",
        )

    ts = timestamp_utc or sorted(events, key=lambda e: e.timestamp_utc)[-1].timestamp_utc
    endpoint_id = endpoint_id or next((e.endpoint_id for e in reversed(events) if e.endpoint_id), None)

    state = _latest_by_type(events, "proxy_state")
    listener = _latest_by_type(events, "listener_state")
    probe = _latest_by_type(events, "probe_result")
    change = _latest_by_type(events, "proxy_change")

    supporting: list[str] = []
    contradicting: list[str] = []
    limitations = list(STANDARD_LIMITATIONS)

    enabled = _bool_field(events, "proxy_state", "wininet_proxy_enabled")
    winhttp_mismatch = _bool_field(events, "proxy_state", "wininet_winhttp_mismatch")
    listener_found = _bool_field(events, "listener_state", "listener_found")
    direct_ok = _bool_field(events, "probe_result", "direct_probe_ok")
    proxy_ok = _bool_field(events, "probe_result", "proxy_probe_ok")
    proxy_status = _str_field(events, "probe_result", "proxy_status")
    listener_name = _str_field(events, "listener_state", "listener_name")
    reverter_status = _str_field(events, "proxy_change", "reverter_status")
    reverter_flag = _bool_field(events, "proxy_change", "reverter_suspected")

    has_writer_proof = any(e.evidence_tier == "T4_WRITER_PROOF" for e in events)

    if state:
        supporting.append(state.evidence_summary)
    if listener:
        supporting.append(listener.evidence_summary)
    if probe:
        supporting.append(probe.evidence_summary)
    if change:
        supporting.append(change.evidence_summary)

    incident_class = "INSUFFICIENT_DATA"
    risk = "UNKNOWN"
    confidence = 0.45
    policy = "observe"
    interpretation = "Endpoint proxy evidence reviewed."

    if reverter_status in ("REVERTER_SUSPECTED", "PROXY_FLAPPING", "REPEATED_LOCALHOST_PROXY_PORTS") or reverter_flag:
        incident_class = "REVERTER_SUSPECTED" if reverter_status != "PROXY_FLAPPING" else "PROXY_FLAPPING"
        if reverter_status == "REPEATED_LOCALHOST_PROXY_PORTS":
            incident_class = "PROXY_FLAPPING"
        risk = "HIGH"
        confidence = 0.8
        policy = "alert_reverter_suspected"
        interpretation = "Proxy settings changed repeatedly — attribution remains correlational without writer proof."
    elif enabled is False and direct_ok is True:
        incident_class = "NO_PROXY_DIRECT_OK"
        risk = "LOW"
        confidence = 0.85
        policy = "observe"
        interpretation = "WinINET proxy disabled and direct path probe succeeded."
    elif enabled is False and direct_ok is False:
        incident_class = "BOTH_DIRECT_AND_PROXY_FAIL"
        risk = "HIGH"
        confidence = 0.7
        policy = "investigate_network_path"
        interpretation = "Proxy disabled but direct connectivity probe failed."
    elif enabled and listener_found is False:
        incident_class = "DEAD_PROXY_CONFIG"
        risk = "HIGH"
        confidence = 0.92
        policy = "block_or_disable_preview"
        interpretation = "WinINET points to localhost proxy but no listener is attributed."
    elif proxy_status == "DIRECT_ONLY_WORKS" or (direct_ok is True and proxy_ok is False and enabled):
        incident_class = "DIRECT_ONLY_WORKS"
        risk = "HIGH"
        confidence = 0.9
        policy = "block_or_disable_preview"
        interpretation = "Direct path works; configured localhost proxy path fails."
    elif proxy_status == "LISTENER_NOT_PROXY":
        incident_class = "LISTENER_NOT_PROXY"
        risk = "HIGH"
        confidence = 0.88
        policy = "alert_high_risk_proxy_transition"
        interpretation = "Port has a listener but does not behave as an HTTP proxy."
    elif proxy_status == "PROXY_FORWARDING_FAILED":
        incident_class = "PROXY_FORWARDING_FAILED"
        risk = "HIGH"
        confidence = 0.86
        policy = "alert_high_risk_proxy_transition"
        interpretation = "Proxy-like listener cannot forward external traffic."
    elif proxy_status in ("BOTH_DIRECT_AND_PROXY_WORK", "HEALTHY_LOCALHOST_PROXY"):
        incident_class = "BOTH_DIRECT_AND_PROXY_WORK"
        risk = "LOW"
        confidence = 0.75
        policy = "observe_or_alert"
        interpretation = "Both direct and proxy paths succeeded; audit whether routing is intended."
    elif proxy_status == "PROXY_ONLY_WORKS" or (proxy_ok is True and direct_ok is False):
        incident_class = "PROXY_ONLY_WORKS"
        risk = "MEDIUM"
        confidence = 0.72
        policy = "observe_or_alert"
        interpretation = "Proxy path works while direct path failed — possible tunnel/VPN dependency."
    elif direct_ok is False and proxy_ok is False:
        incident_class = "BOTH_DIRECT_AND_PROXY_FAIL"
        risk = "HIGH"
        confidence = 0.78
        policy = "investigate_network_path"
        interpretation = "Both direct and proxy probes failed."
    elif enabled and listener_found and proxy_ok is None:
        incident_class = "LOCAL_PROXY_ACTIVE"
        risk = "MEDIUM"
        confidence = 0.65
        policy = "observe_or_alert"
        interpretation = "Localhost listener present; path probes incomplete."
    elif enabled and listener_found:
        incident_class = "LOCAL_PROXY_ACTIVE"
        risk = "MEDIUM"
        confidence = 0.7
        policy = "observe_or_alert"
        interpretation = f"Localhost proxy active; listener appears to be {listener_name or 'unknown'}."
    elif enabled:
        incident_class = "UNKNOWN_LOCAL_PROXY"
        risk = "HIGH"
        confidence = 0.55
        policy = "human_review"
        interpretation = "Proxy enabled but listener and probe evidence incomplete."

    if listener_name and listener_name.lower() in _DEV_TRUSTED and incident_class in (
        "LOCAL_PROXY_ACTIVE",
        "BOTH_DIRECT_AND_PROXY_WORK",
        "UNKNOWN_LOCAL_PROXY",
    ):
        risk = "MEDIUM" if incident_class != "UNKNOWN_LOCAL_PROXY" else "MEDIUM"

    if winhttp_mismatch:
        supporting.append("WinINET enabled while WinHTTP reports direct access.")
        if incident_class not in ("REVERTER_SUSPECTED", "PROXY_FLAPPING", "DEAD_PROXY_CONFIG"):
            incident_class = "WININET_WINHTTP_MISMATCH"
            if risk in ("LOW", "UNKNOWN"):
                risk = "MEDIUM"
            confidence = max(confidence, 0.72)

    if listener_found and listener_name and not has_writer_proof:
        limitations.append("Likely process / correlation only; registry writer proof unavailable.")

    stale = _str_field(events, "proxy_change", "reverter_status") == "STALE_PROXY_AFTER_PROCESS_EXIT"
    if stale:
        incident_class = "STALE_PROXY_AFTER_PROCESS_EXIT"
        risk = "HIGH"
        interpretation = "Proxy remains enabled after listener exited."

    return IncidentRecord(
        incident_id=make_incident_id(ts, incident_class, endpoint_id),
        timestamp_utc=ts,
        endpoint_id=endpoint_id,
        incident_class=incident_class,
        risk_level=risk,
        confidence=confidence,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        limitations=limitations,
        recommended_policy_action=policy,
        human_interpretation=interpretation,
    )


def classify_incidents_from_events(events: list[EvidenceEvent]) -> list[IncidentRecord]:
    """Group events by endpoint and classify one incident per endpoint bundle.

    Args:
        events: All normalized events from a pipeline run.

    Returns:
        One ``IncidentRecord`` per distinct ``endpoint_id`` (or single ``local`` bucket).
        Empty input returns [].
    """
    if not events:
        return []
    by_endpoint: dict[str, list[EvidenceEvent]] = {}
    for ev in events:
        key = ev.endpoint_id or "local"
        by_endpoint.setdefault(key, []).append(ev)
    incidents: list[IncidentRecord] = []
    for endpoint_id, group in sorted(by_endpoint.items()):
        incidents.append(
            classify_incident_from_events(
                group,
                endpoint_id=None if endpoint_id == "local" else endpoint_id,
            )
        )
    return incidents
