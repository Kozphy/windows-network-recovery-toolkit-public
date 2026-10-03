"""Policy engine models — Step 3."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from src.classification.models import ProcessClassificationResult


class PolicyDecisionKind(StrEnum):
    """Represent policy decision kind data used by the toolkit.

    Attributes:
        ALLOW: Field or variant describing a l l o w evidence or state.
        OBSERVE: Field or variant describing o b s e r v e evidence or state.
        ALERT: Field or variant describing a l e r t evidence or state.
        PREVIEW_DISABLE: Field or variant describing p r e v i e w d i s a b l e evidence or state.
        REQUIRE_CONFIRMATION: Field or variant describing r e q u i r e c o n f i r m a t i o n evidence or state.
        BLOCK_RECOMMENDED: Field or variant describing b l o c k r e c o m m e n d e d evidence or state.
        ESCALATE_REVIEW: Field or variant describing e s c a l a t e r e v i e w evidence or state.
        CORRELATION_ONLY_ALERT: Field or variant describing c o r r e l a t i o n o n l y a l e r t evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    ALLOW = "ALLOW"
    OBSERVE = "OBSERVE"
    ALERT = "ALERT"
    PREVIEW_DISABLE = "PREVIEW_DISABLE"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    BLOCK_RECOMMENDED = "BLOCK_RECOMMENDED"
    ESCALATE_REVIEW = "ESCALATE_REVIEW"
    CORRELATION_ONLY_ALERT = "CORRELATION_ONLY_ALERT"


class PolicySeverity(StrEnum):
    """Represent policy severity data used by the toolkit.

    Attributes:
        LOW: Field or variant describing l o w evidence or state.
        MEDIUM: Field or variant describing m e d i u m evidence or state.
        HIGH: Field or variant describing h i g h evidence or state.
        CRITICAL: Field or variant describing c r i t i c a l evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ProxyPolicyUserConfig:
    """Represent proxy policy user config data used by the toolkit.

    Attributes:
        allow_known_cursor: Field or variant describing allow known cursor evidence or state.
        cursor_action: Field or variant describing cursor action evidence or state.
        vscode_action: Field or variant describing vscode action evidence or state.
        dev_proxy_action: Field or variant describing dev proxy action evidence or state.
        active_dev_session: Field or variant describing active dev session evidence or state.
        deny_unknown_localhost: Field or variant describing deny unknown localhost evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    allow_known_cursor: bool = True
    cursor_action: str = "OBSERVE"
    vscode_action: str = "OBSERVE"
    dev_proxy_action: str = "OBSERVE"
    active_dev_session: bool = True
    deny_unknown_localhost: bool = True

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProxyPolicyUserConfig:
        """From dict.

        Args:
            raw: The raw value supplied by the caller.

        Returns:
            The ProxyPolicyUserConfig result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return cls(
            allow_known_cursor=bool(raw.get("allow_known_cursor", True)),
            cursor_action=str(raw.get("cursor_proxy_action", raw.get("cursor_action", "OBSERVE"))),
            vscode_action=str(
                raw.get("vscode_extension_action", raw.get("vscode_action", "OBSERVE"))
            ),
            dev_proxy_action=str(
                raw.get("known_dev_proxy_action", raw.get("dev_proxy_action", "OBSERVE"))
            ),
            active_dev_session=bool(raw.get("active_dev_session", True)),
            deny_unknown_localhost=bool(
                raw.get("deny_unknown_localhost_proxy", raw.get("deny_unknown_localhost", True))
            ),
        )


@dataclass
class ProxyPolicyInput:
    """Represent proxy policy input data used by the toolkit.

    Attributes:
        causation_level: Field or variant describing causation level evidence or state.
        classification_result: Field or variant describing classification result evidence or state.
        proxy_before: Field or variant describing proxy before evidence or state.
        proxy_after: Field or variant describing proxy after evidence or state.
        registry_writer: Field or variant describing registry writer evidence or state.
        registry_target: Field or variant describing registry target evidence or state.
        registry_details: Field or variant describing registry details evidence or state.
        localhost_port: Field or variant describing localhost port evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    causation_level: str
    classification_result: ProcessClassificationResult | dict[str, Any]
    proxy_before: dict[str, Any]
    proxy_after: dict[str, Any]
    registry_writer: str | None = None
    registry_target: str | None = None
    registry_details: str | None = None
    localhost_port: int | None = None
    user_config: ProxyPolicyUserConfig | None = None
    timestamp_utc: str = ""
    changed_fields: list[str] = field(default_factory=list)
    risk_level: str | None = None


@dataclass
class ProxyPolicyDecision:
    """Represent proxy policy decision data used by the toolkit.

    Attributes:
        decision: Field or variant describing decision evidence or state.
        severity: Field or variant describing severity evidence or state.
        allowed_actions: Field or variant describing allowed actions evidence or state.
        blocked_actions: Field or variant describing blocked actions evidence or state.
        requires_confirmation: Field or variant describing requires confirmation evidence or state.
        reason: Field or variant describing reason evidence or state.
        explanation: Field or variant describing explanation evidence or state.
        next_safe_steps: Field or variant describing next safe steps evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    decision: PolicyDecisionKind
    severity: PolicySeverity
    allowed_actions: list[str] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)
    requires_confirmation: bool = False
    reason: str = ""
    explanation: list[str] = field(default_factory=list)
    next_safe_steps: list[str] = field(default_factory=list)

    @property
    def action(self) -> str:
        """Action.

        Args:
            None.

        Returns:
            The str result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self.decision.value

    @property
    def confidence(self) -> float:
        """Confidence.

        Args:
            None.

        Returns:
            The float result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {"LOW": 0.5, "MEDIUM": 0.65, "HIGH": 0.82, "CRITICAL": 0.92}.get(
            self.severity.value, 0.6
        )

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
            "decision": self.decision.value,
            "action": self.decision.value,
            "severity": self.severity.value,
            "allowed_actions": list(self.allowed_actions),
            "blocked_actions": list(self.blocked_actions),
            "requires_confirmation": self.requires_confirmation,
            "reason": self.reason,
            "explanation": list(self.explanation),
            "next_safe_steps": list(self.next_safe_steps),
            "confidence": self.confidence,
            "requires_human_review": self.requires_confirmation,
        }
