"""Decision envelope — technical + organizational layers kept distinct."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.platform_core.stakeholder.models import StakeholderContext
from src.platform_core.timing.models import TimingContext

SCHEMA_DECISION_CONTEXT = "decision_context.v1"


class CoordinationStatus(StrEnum):
    """Represent the coordination status enum.

    Variants:
        READY: Structured value carried by this enum.
        NEEDS_OWNER: Structured value carried by this enum.
        NEEDS_APPROVAL: Structured value carried by this enum.
        DEFERRED_TO_WINDOW: Structured value carried by this enum.
        ESCALATE_NOW: Structured value carried by this enum.
        MONITOR_UNTIL: Structured value carried by this enum.
        EXPIRED: Structured value carried by this enum.
        BLOCKED_BY_CHANGE_FREEZE: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    READY = "READY"
    NEEDS_OWNER = "NEEDS_OWNER"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    DEFERRED_TO_WINDOW = "DEFERRED_TO_WINDOW"
    ESCALATE_NOW = "ESCALATE_NOW"
    MONITOR_UNTIL = "MONITOR_UNTIL"
    EXPIRED = "EXPIRED"
    BLOCKED_BY_CHANGE_FREEZE = "BLOCKED_BY_CHANGE_FREEZE"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


class DecisionEnvelope(BaseModel):
    """Versioned orchestration envelope — does not mutate evidence or policy schemas."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_DECISION_CONTEXT
    case_id: str
    decision_id: str = ""
    evidence_refs: tuple[str, ...] = ()
    ranked_hypotheses: tuple[dict[str, Any], ...] = ()
    proof_result: dict[str, Any] = Field(default_factory=dict)
    policy_decision: str = "PREVIEW_ONLY"
    policy_allowed: bool = False
    policy_requires_approval: bool = True
    stakeholder: StakeholderContext | None = None
    timing: TimingContext | None = None
    coordination_status: CoordinationStatus = CoordinationStatus.NEEDS_APPROVAL
    remediation_preview: dict[str, Any] = Field(default_factory=dict)
    rollback_requirements: tuple[str, ...] = (
        "Capture current WinINET proxy values before any apply.",
        "Typed confirmation token required for registry mutation.",
    )
    audit_metadata: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = (
        "Observation is not proof.",
        "Correlation is not causation.",
        "Confidence is not certainty.",
        "Classification is not accusation.",
        "Policy permission is not a safety guarantee.",
        "Stakeholder assignment is not approval.",
        "A valid maintenance window is not execution authorization.",
        "Remediation remains preview-only by default.",
    )
    non_claims: tuple[str, ...] = (
        "Does not authorize silent destructive action.",
        "Does not bypass typed confirmation via urgency.",
        "Does not invent stakeholder identities.",
    )

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return self.model_dump(mode="json")
