"""Map incident type and ordinal confidence to a risk level tier.

Module responsibility:
    Provide a single deterministic function that translates an ``IncidentType``
    and a confidence score into an ordinal risk level (``"low"`` / ``"medium"``
    / ``"high"``).  The mapping is policy-driven, not ML-derived.

System placement:
    Called exclusively by ``hypothesis_engine.evaluate_incident`` to populate
    ``DecisionResult.risk_level``.

Key invariants:
    * ``SUSPICIOUS_PROXY``, ``POSSIBLE_MITM_RISK``, and
      ``WRITER_AND_LISTENER_MATCH`` always resolve to ``"high"`` regardless
      of confidence — these patterns carry the highest remediation urgency.
    * ``UNKNOWN_LOCAL_PROXY`` escalates from ``"medium"`` to ``"high"`` when
      confidence reaches or exceeds 0.8 — a high-confidence unknown listener
      is treated more conservatively.
    * Risk level is a classification tier, not a probability; it drives
      operator action priorities, not autonomous decisions.

Side effects:
    None — pure function.
"""

from __future__ import annotations

from .decision_model import IncidentType, RiskLevel


def classify_risk(incident: IncidentType, confidence: float) -> RiskLevel:
    """Classify the risk level for an incident type and confidence score.

    Args:
        incident: The resolved ``IncidentType`` from ``evaluate_incident``.
        confidence: Ordinal analytic confidence in ``[0.0, 1.0]``.

    Returns:
        ``"high"`` for inherently high-risk incident types or a high-confidence
        unknown listener; ``"medium"`` for intermediate incident types;
        ``"low"`` for no-proxy and known-tool patterns.
    """
    high_risk = {
        IncidentType.SUSPICIOUS_PROXY,
        IncidentType.POSSIBLE_MITM_RISK,
        IncidentType.WRITER_AND_LISTENER_MATCH,
    }
    medium_risk = {
        IncidentType.WININET_PROXY_DRIFT,
        IncidentType.PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS,
        IncidentType.UNKNOWN_LOCAL_PROXY,
        IncidentType.REGISTRY_REWRITER_OBSERVED,
        IncidentType.DNS_OK_BROWSER_FAIL,
    }
    if incident in high_risk or (
        incident == IncidentType.UNKNOWN_LOCAL_PROXY and confidence >= 0.8
    ):
        return "high"
    if incident in medium_risk:
        return "medium"
    return "low"
