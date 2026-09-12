"""Escalation path construction — organizational only."""

from __future__ import annotations

from src.platform_core.stakeholder.models import (
    EscalationHop,
    RoleRef,
    StakeholderReasonCode,
    StakeholderResolutionSource,
)
from src.platform_core.stakeholder.registry import (
    SECURITY_ESCALATION_CLASSIFICATIONS,
    role_display,
)


def build_escalation_path(
    *,
    classification: str,
    primary_escalation: RoleRef,
    security_required: bool | None = None,
) -> tuple[EscalationHop, ...]:
    """Build a deterministic escalation ladder of roles."""
    hops: list[EscalationHop] = [
        EscalationHop(
            order=1,
            role=primary_escalation,
            trigger="primary_escalation",
        )
    ]
    need_security = (
        security_required
        if security_required is not None
        else str(classification).upper() in SECURITY_ESCALATION_CLASSIFICATIONS
    )
    if need_security:
        hops.append(
            EscalationHop(
                order=2,
                role=RoleRef(
                    role_id="security_incident_manager",
                    display_name=role_display("security_incident_manager"),
                    source=StakeholderResolutionSource.CLASSIFICATION_MAPPING,
                    reason_code=StakeholderReasonCode.SECURITY_ESCALATION_REQUIRED,
                    rationale="Classification maps to security escalation path.",
                ),
                trigger="security_escalation_required",
            )
        )
    return tuple(hops)
