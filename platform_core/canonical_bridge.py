"""Compatibility bridge: legacy ``platform_core`` imports → ``src.platform_core``.

Prefer ``from src.platform_core.evidence import ...`` for new code.
"""

from __future__ import annotations

import warnings

from src.platform_core.evidence.guards import (
    can_unlock_destructive_remediation,
    requires_proof_for_final_causation,
)
from src.platform_core.evidence.state_machine import EvidenceStateMachine
from src.platform_core.evidence.tiers import TIER_ORDER, EvidenceTier

__all__ = [
    "EvidenceStateMachine",
    "EvidenceTier",
    "TIER_ORDER",
    "can_unlock_destructive_remediation",
    "requires_proof_for_final_causation",
]


def _warn() -> None:
    warnings.warn(
        "platform_core.canonical_bridge is a compatibility shim; use src.platform_core",
        DeprecationWarning,
        stacklevel=3,
    )
