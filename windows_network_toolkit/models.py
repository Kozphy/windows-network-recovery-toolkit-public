"""Unified WNT data models — JSON-serializable at CLI boundary.

Module responsibility:
    Define dataclasses converted to dicts at CLI/API boundaries: proxy state, process owner,
    classification, proof, audit events, and policy decisions.

System placement:
    Shared contract between collectors (``proxy_state``), reporters, and ``audit_store``.

Key invariants:
    * All ``to_dict()`` methods produce JSON-serializable primitives.
    * ``ProofResult`` includes ``confidence_display`` for human-readable ordinal confidence.
    * Timestamps are caller-supplied UTC strings — this module does not generate them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.platform_core.principles.rules import format_confidence_display


@dataclass
class ProxyState:
    """Snapshot of WinINET and WinHTTP proxy configuration for one collection run.

    Attributes:
        timestamp_utc: UTC timestamp of the collection in ISO-8601 ``%Y-%m-%dT%H:%M:%SZ`` format.
        wininet_proxy_enabled: True when ``HKCU\\...\\Internet Settings\\ProxyEnable`` is 1.
        wininet_proxy_server: Raw ``ProxyServer`` registry string (may be empty).
        wininet_proxy_override: Raw ``ProxyOverride`` bypass list string.
        wininet_auto_config_url: PAC/WPAD URL from ``AutoConfigURL`` registry value.
        winhttp_direct_access: True when ``netsh winhttp show proxy`` shows DIRECT.
        winhttp_raw_excerpt: First 400 characters of ``netsh winhttp show proxy`` output.
        localhost_port: Parsed loopback port from ``wininet_proxy_server``; None when absent.
        source: Collector identity tag (default ``wininet_registry+netsh_winhttp``).
        errors: Non-fatal collection errors accumulated during the run.
    """

    timestamp_utc: str
    wininet_proxy_enabled: bool
    wininet_proxy_server: str
    wininet_proxy_override: str
    wininet_auto_config_url: str
    winhttp_direct_access: bool
    winhttp_raw_excerpt: str
    localhost_port: int | None
    source: str = "wininet_registry+netsh_winhttp"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for CLI/API output."""
        return {
            "timestamp_utc": self.timestamp_utc,
            "wininet_proxy_enabled": self.wininet_proxy_enabled,
            "wininet_proxy_server": self.wininet_proxy_server,
            "wininet_proxy_override": self.wininet_proxy_override,
            "wininet_auto_config_url": self.wininet_auto_config_url,
            "winhttp_direct_access": self.winhttp_direct_access,
            "winhttp_raw_excerpt": self.winhttp_raw_excerpt,
            "localhost_port": self.localhost_port,
            "source": self.source,
            "errors": self.errors,
        }


@dataclass
class ProcessOwner:
    """Process attribution result for a localhost proxy listener port.

    Attributes:
        listener_found: True when a process was successfully resolved on the proxy port.
        pid: OS process ID; None when the listener was not found.
        name: Executable name (e.g. ``node.exe``).
        exe_path: Full path to the process executable.
        cmdline: Command-line string; may be truncated or empty without elevated privileges.
        username: Windows session username of the listener process.
        signed_status: Authenticode signature status string (e.g. ``signed``, ``unsigned``).
        errors: Non-fatal resolution errors (e.g. permission denied).
    """

    listener_found: bool
    pid: int | None = None
    name: str = ""
    exe_path: str = ""
    cmdline: str = ""
    username: str = ""
    signed_status: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict; always includes ``listener_found`` flag."""
        if not self.listener_found:
            return {
                "listener_found": False,
                "pid": self.pid,
                "name": self.name,
                "exe_path": self.exe_path,
                "cmdline": self.cmdline,
                "username": self.username,
                "signed_status": self.signed_status,
                "errors": self.errors,
            }
        return {
            "listener_found": True,
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "username": self.username,
            "signed_status": self.signed_status,
            "errors": self.errors,
        }


@dataclass
class ClassificationResult:
    """Classifier output for a single proxy incident observation.

    Attributes:
        primary_classification: Primary incident class label (e.g. ``REVERTER_SUSPECTED``).
        secondary_signals: Additional classification signals observed alongside the primary.
        severity: Ordinal severity band: ``info``, ``warning``, or ``error``.
        confidence: Classifier confidence in [0.0, 1.0]; not a calibrated probability.
        reasoning: Human-readable explanation of how inputs produced this classification.
        evidence: Ordered evidence lines supporting the classification.
        recommended_next_actions: Suggested diagnostic or policy actions for operators.
        limitations: Mandatory epistemic caveats; always non-empty.
    """

    primary_classification: str
    secondary_signals: list[str]
    severity: str
    confidence: float
    reasoning: str
    evidence: list[str]
    recommended_next_actions: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict with confidence rounded to 3 decimal places."""
        return {
            "primary_classification": self.primary_classification,
            "secondary_signals": self.secondary_signals,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "recommended_next_actions": self.recommended_next_actions,
            "limitations": self.limitations,
        }


@dataclass
class ProofAttempt:
    """One step in a structured proof chain (Observation → Hypothesis → Proof).

    Attributes:
        name: Short identifier for this proof step (e.g. ``sysmon_event_13_check``).
        status: Outcome of the attempt: ``found``, ``not_found``, ``inconclusive``, etc.
        meaning: Plain-English interpretation of this step's result for audit consumers.
    """

    name: str
    status: str
    meaning: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {"name": self.name, "status": self.status, "meaning": self.meaning}


@dataclass
class ProofResult:
    """Full structured proof envelope for one hypothesis.

    Attributes:
        observation: Raw observation fields that triggered this proof run.
        hypothesis: The claim being tested (e.g. ``localhost proxy listener present``).
        proof_attempts: Ordered list of ``ProofAttempt`` steps executed.
        conclusion_status: Overall outcome: ``SUPPORTED``, ``UNSUPPORTED``, ``INCONCLUSIVE``, etc.
        confidence: Aggregate confidence in [0.0, 1.0]; not a statistical probability.
        limitations: Mandatory epistemic caveats; always non-empty.
    """

    observation: dict[str, Any]
    hypothesis: str
    proof_attempts: list[ProofAttempt]
    conclusion_status: str
    confidence: float
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict including ``confidence_display`` (human ordinal)."""
        return {
            "observation": self.observation,
            "hypothesis": self.hypothesis,
            "proof_attempts": [p.to_dict() for p in self.proof_attempts],
            "conclusion": {
                "status": self.conclusion_status,
                "confidence": round(self.confidence, 3),
                "confidence_display": format_confidence_display(self.confidence),
            },
            "limitations": self.limitations,
            "confidence_display": format_confidence_display(self.confidence),
        }


@dataclass
class AuditEvent:
    """Immutable audit record for one CLI command execution.

    Attributes:
        timestamp_utc: UTC timestamp of the event in ``%Y-%m-%dT%H:%M:%SZ`` format.
        command: CLI command name that produced this event (e.g. ``proxy-disable``).
        observation: Evidence fields observed before the action was requested.
        hypothesis: The claim or suspicion that motivated the command.
        action_requested: What the operator requested (e.g. ``disable_wininet_proxy``).
        action_allowed: Whether the policy gate permitted the action.
        action_taken: What was actually executed (may be ``dry_run_preview`` when dry_run=True).
        confirmation_used: The typed confirmation token provided by the operator.
        result: Outcome fields from the action or preview.
        limitations: Epistemic caveats attached to this audit record.
    """

    timestamp_utc: str
    command: str
    observation: dict[str, Any]
    hypothesis: str
    action_requested: str
    action_allowed: bool
    action_taken: str
    confirmation_used: str
    result: dict[str, Any]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for JSONL audit storage."""
        return {
            "timestamp_utc": self.timestamp_utc,
            "command": self.command,
            "observation": self.observation,
            "hypothesis": self.hypothesis,
            "action_requested": self.action_requested,
            "action_allowed": self.action_allowed,
            "action_taken": self.action_taken,
            "confirmation_used": self.confirmation_used,
            "result": self.result,
            "limitations": self.limitations,
        }


@dataclass
class PolicyDecision:
    """Policy gate evaluation result for a requested remediation action.

    Attributes:
        action: The remediation action evaluated (e.g. ``disable_wininet_proxy``).
        allowed: True when the action is permitted under current policy.
        requires_confirmation: True when the operator must supply a typed token.
        confirmation_token: Expected token string that the operator must type verbatim.
        risk_level: Ordinal risk band: ``low``, ``medium``, ``high``, or ``critical``.
        rationale: Human-readable explanation of why the action is allowed or denied.
        safety_checks: List of safety gate names evaluated before the decision.
    """

    action: str
    allowed: bool
    requires_confirmation: bool
    confirmation_token: str
    risk_level: str
    rationale: str
    safety_checks: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for policy audit and CLI output."""
        return {
            "action": self.action,
            "allowed": self.allowed,
            "requires_confirmation": self.requires_confirmation,
            "confirmation_token": self.confirmation_token,
            "risk_level": self.risk_level,
            "rationale": self.rationale,
            "safety_checks": self.safety_checks,
        }
