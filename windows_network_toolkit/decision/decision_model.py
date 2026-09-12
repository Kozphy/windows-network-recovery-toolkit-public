"""Decision result models for the Endpoint Reliability Decision Platform.

Module responsibility:
    Define the canonical Pydantic models and enumerations that carry a
    completed decision through the platform: the ``IncidentType`` enumeration
    of supported proxy-risk scenarios, and the ``DecisionResult`` that records
    the chosen incident type, confidence, risk level, recommended action, and
    all policy-gate flags.

System placement:
    Shared data contract between ``hypothesis_engine``, ``risk_classifier``,
    ``remediation_planner``, and the ``platform`` API layer.  Also serialised
    into audit JSONL records via ``model_dump()``.

Key invariants:
    * ``confidence`` is bounded to ``[0.0, 1.0]`` by Pydantic validation.
    * ``requires_confirmation`` defaults to ``True``; callers must not execute
      any mutating action without an explicit typed confirmation token.
    * ``human_review_required=True`` on incident types that involve uncertain
      or escalated risk (``SUSPICIOUS_PROXY``, ``POSSIBLE_MITM_RISK``,
      ``REGISTRY_REWRITER_OBSERVED``).
    * Classification is a hypothesis: ``IncidentType`` labels describe observed
      proxy behaviour patterns, not attribution or intent.

Side effects:
    None — pure data models with no I/O.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["low", "medium", "high", "critical"]


class IncidentType(StrEnum):
    """Enumeration of observable proxy-risk incident patterns.

    Each member corresponds to a distinct hypothesis about the Windows endpoint
    proxy configuration state.  Members are mutually exclusive within a single
    ``DecisionResult`` but multiple hypotheses may be ranked by
    ``hypothesis_engine`` before the top one is selected.

    Members:
        NO_PROXY: No proxy configuration signal detected.
        KNOWN_DEV_PROXY: Recognised developer proxy (e.g. Fiddler, Charles) —
            observe only.
        KNOWN_SECURITY_TOOL: Recognised security inspection tool — observe only.
        UNKNOWN_LOCAL_PROXY: Localhost listener with no known attribution.
        SUSPICIOUS_PROXY: Listener exhibiting suspicious characteristics;
            human review required.
        POSSIBLE_MITM_RISK: Pattern consistent with TLS interception risk;
            human review required.
        WININET_PROXY_DRIFT: WinInet proxy setting diverges from expected
            baseline.
        REGISTRY_REWRITER_OBSERVED: A process was observed writing to the
            proxy registry path.
        WRITER_AND_LISTENER_MATCH: Registry writer and localhost listener
            corroborate each other — highest-confidence reverter pattern.
        DNS_OK_BROWSER_FAIL: DNS resolves correctly but browser proxy path
            fails — indicates proxy-path configuration issue.
        PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS: Proxy path fails while direct
            path succeeds — supports disabling the proxy setting.
    """

    NO_PROXY = "NO_PROXY"
    KNOWN_DEV_PROXY = "KNOWN_DEV_PROXY"
    KNOWN_SECURITY_TOOL = "KNOWN_SECURITY_TOOL"
    UNKNOWN_LOCAL_PROXY = "UNKNOWN_LOCAL_PROXY"
    SUSPICIOUS_PROXY = "SUSPICIOUS_PROXY"
    POSSIBLE_MITM_RISK = "POSSIBLE_MITM_RISK"
    WININET_PROXY_DRIFT = "WININET_PROXY_DRIFT"
    REGISTRY_REWRITER_OBSERVED = "REGISTRY_REWRITER_OBSERVED"
    WRITER_AND_LISTENER_MATCH = "WRITER_AND_LISTENER_MATCH"
    DNS_OK_BROWSER_FAIL = "DNS_OK_BROWSER_FAIL"
    PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS = "PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS"


class DecisionResult(BaseModel):
    """The output of one hypothesis-evaluation cycle.

    Carries the selected incident type, ordinal confidence, risk level,
    recommended action, and all policy-gate flags needed for the remediation
    planner and audit trail.

    Attributes:
        decision_id: Unique decision identifier (``"dec-<hex>``" format).
        incident_id: Identifier of the evidence bundle / incident this decision
            relates to.
        incident_type: Winning hypothesis from ``IncidentType``.
        confidence: Ordinal analytic confidence in ``[0.0, 1.0]``.  Not a
            calibrated probability.
        risk_level: Ordinal risk tier (``"low"`` / ``"medium"`` / ``"high"``
            / ``"critical"``).
        recommended_action: Token string naming the next operator action
            (e.g. ``"DISABLE_WININET_PROXY_WITH_CONFIRMATION"``).
        requires_confirmation: ``True`` when a typed confirmation phrase is
            required before execution.
        reasoning: Human-readable explanation of the decision, including the
            confidence narrative.
        evidence_refs: Signal names and evidence IDs that supported the
            decision.
        blocked_actions: Actions explicitly blocked by safety policy for this
            incident.
        allowed_actions: Actions permitted by policy for this incident.
        rollback_plan: Description of the rollback available after remediation.
        human_review_required: ``True`` for incident types that must not be
            acted upon without analyst review.
        metadata: Arbitrary extension dict; used to carry ranked hypothesis
            lists and other diagnostic information.
    """

    decision_id: str
    incident_id: str
    incident_type: IncidentType
    confidence: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel = "medium"
    recommended_action: str = ""
    requires_confirmation: bool = True
    reasoning: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    rollback_plan: str = ""
    human_review_required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
