"""Stakeholder resolution — organizational ownership separate from technical proof."""

from __future__ import annotations

from src.platform_core.stakeholder.models import (
    SCHEMA_STAKEHOLDER,
    EscalationHop,
    RoleRef,
    StakeholderContext,
    StakeholderReasonCode,
    StakeholderResolutionSource,
)
from src.platform_core.stakeholder.resolver import StakeholderResolver, resolve_stakeholders

__all__ = [
    "SCHEMA_STAKEHOLDER",
    "EscalationHop",
    "RoleRef",
    "StakeholderContext",
    "StakeholderReasonCode",
    "StakeholderResolutionSource",
    "StakeholderResolver",
    "resolve_stakeholders",
]
