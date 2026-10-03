"""Typed models for network recovery scenario runs.

Module responsibility:
    Define frozen/dataclass contracts for signals, hypotheses, remediation previews,
    and audit-serializable diagnosis results.

System placement:
    Shared by collectors, engine, scenarios, remediation_executor, and audit.

Key invariants:
    * ``SignalBundle`` is observation-only; no inference fields.
    * ``timestamp`` on ``DiagnosisResult`` is UTC ISO-8601 (set by engine).
    * ``OrdinalConfidence`` is ordinal rank, not calibrated probability.

Data shape:
    ``to_audit_dict()`` flattens primary hypothesis evidence for JSONL append-only logs.

Side effects:
    None — pure data structures.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

CASE_CHATGPT_APP_FIREWALL_FILTERING_INTERACTION = "CASE_CHATGPT_APP_FIREWALL_FILTERING_INTERACTION"
SCENARIO_CHATGPT_APP_FIREWALL = "chatgpt_app_firewall"

OrdinalConfidence = Literal["low", "medium", "high"]
PolicyOutcome = Literal["ALLOW", "PREVIEW", "BLOCK"]
VerificationStatus = Literal[
    "not_run",
    "inconclusive",
    "supported_by_recovery_evidence",
    "contradicted_by_recovery_evidence",
]
RiskTier = Literal["low", "medium", "high", "blocked"]

DESKTOP_APP_PATH_DEGRADED_EVENT = "desktop_app_path_degraded_browser_healthy"

HYPOTHESIS_IDS = (
    "firewall_filtering_interaction",
    "electron_network_stack_issue",
    "app_cache_or_session_issue",
    "proxy_or_localhost_proxy_interaction",
    "vpn_or_security_filter_driver_interaction",
)


@dataclass(frozen=True)
class SignalBundle:
    """Observation layer: collectors only; no causality claims."""

    browser_https_ok: bool | None
    chatgpt_https_ok: bool | None
    openai_https_ok: bool | None
    curl_https_ok: bool | None
    dns_ok: bool | None
    wininet_proxy_enable: int | None
    wininet_proxy_server: str | None
    wininet_auto_config_url: str | None
    winhttp_direct_access: bool | None
    winhttp_loopback_hint: bool
    firewall_profiles_snapshot: dict[str, Any]
    localhost_listener_ports: tuple[int, ...]
    chatgpt_process_detected: bool
    electron_process_detected: bool
    vpn_adapter_hint: bool
    collector_notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """To dict.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "browser_https_ok": self.browser_https_ok,
            "chatgpt_https_ok": self.chatgpt_https_ok,
            "openai_https_ok": self.openai_https_ok,
            "curl_https_ok": self.curl_https_ok,
            "dns_ok": self.dns_ok,
            "wininet_proxy_enable": self.wininet_proxy_enable,
            "wininet_proxy_server": self.wininet_proxy_server,
            "wininet_auto_config_url": self.wininet_auto_config_url,
            "winhttp_direct_access": self.winhttp_direct_access,
            "winhttp_loopback_hint": self.winhttp_loopback_hint,
            "firewall_profiles_snapshot": dict(self.firewall_profiles_snapshot),
            "localhost_listener_ports": list(self.localhost_listener_ports),
            "chatgpt_process_detected": self.chatgpt_process_detected,
            "electron_process_detected": self.electron_process_detected,
            "vpn_adapter_hint": self.vpn_adapter_hint,
            "collector_notes": list(self.collector_notes),
        }


@dataclass(frozen=True)
class RankedHypothesis:
    """Represent ranked hypothesis data used by the toolkit.

    Attributes:
        hypothesis_id: Field or variant describing hypothesis id evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        evidence_for: Field or variant describing evidence for evidence or state.
        evidence_against: Field or variant describing evidence against evidence or state.
        limitations: Field or variant describing limitations evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    hypothesis_id: str
    confidence: OrdinalConfidence
    evidence_for: tuple[str, ...]
    evidence_against: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """To dict.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "hypothesis_id": self.hypothesis_id,
            "confidence": self.confidence,
            "evidence_for": list(self.evidence_for),
            "evidence_against": list(self.evidence_against),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class RemediationActionPreview:
    """Represent remediation action preview data used by the toolkit.

    Attributes:
        action_id: Field or variant describing action id evidence or state.
        title: Field or variant describing title evidence or state.
        risk: Field or variant describing risk evidence or state.
        policy_decision: Field or variant describing policy decision evidence or state.
        dry_run_only: Field or variant describing dry run only evidence or state.
        detail: Field or variant describing detail evidence or state.
        script_or_command_preview: Field or variant describing script or command preview evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    action_id: str
    title: str
    risk: RiskTier
    policy_decision: PolicyOutcome
    dry_run_only: bool
    detail: str
    script_or_command_preview: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """To dict.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "action_id": self.action_id,
            "title": self.title,
            "risk": self.risk,
            "policy_decision": self.policy_decision,
            "dry_run_only": self.dry_run_only,
            "detail": self.detail,
            "script_or_command_preview": self.script_or_command_preview,
        }


@dataclass
class DiagnosisResult:
    """Inference + policy layer for one scenario run."""

    run_id: str
    scenario_id: str
    canonical_case: str
    timestamp: str
    signals: SignalBundle
    events: list[str]
    hypotheses: list[RankedHypothesis]
    confidence_boundary: str
    recommended_actions: list[RemediationActionPreview]
    policy_decision: PolicyOutcome
    verification_status: VerificationStatus
    human_summary: str
    limitations: list[str]
    post_check_results: dict[str, Any] = field(default_factory=dict)
    remediation_executed: list[str] = field(default_factory=list)

    def to_audit_dict(self) -> dict[str, Any]:
        """To audit dict.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        primary = self.hypotheses[0] if self.hypotheses else None
        return {
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "canonical_case": self.canonical_case,
            "signals": self.signals.to_dict(),
            "events": list(self.events),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "evidence_for": list(primary.evidence_for) if primary else [],
            "evidence_against": list(primary.evidence_against) if primary else [],
            "confidence_boundary": self.confidence_boundary,
            "recommended_actions": [a.to_dict() for a in self.recommended_actions],
            "policy_decision": self.policy_decision,
            "remediation_executed": list(self.remediation_executed),
            "post_check_results": dict(self.post_check_results),
            "limitations": list(self.limitations),
            "verification_status": self.verification_status,
            "human_summary": self.human_summary,
        }


@dataclass(frozen=True)
class AuditRecord:
    """Append-only JSONL row for logs/network_recovery_events.jsonl."""

    payload: dict[str, Any]

    @staticmethod
    def from_diagnosis(result: DiagnosisResult) -> AuditRecord:
        """From diagnosis.

        Args:
            result: The result value supplied by the caller.

        Returns:
            The AuditRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return AuditRecord(payload=result.to_audit_dict())


def new_run_id() -> str:
    """New run id.

    Args:
        None.

    Returns:
        The str result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return f"nr_{uuid.uuid4().hex}"
