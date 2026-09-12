"""Evidence package interfaces for typed observations and proof tiers.

Module responsibility:
    Expose package-level interfaces without performing runtime work.

System placement:
    Imported by platform modules that need the package namespace.

Key invariants:
    Importing this package must not collect evidence or mutate state.

Side effects:
    None.
"""

from .guards import can_unlock_destructive_remediation, validate_tier_upgrade
from .state_machine import EvidenceStateMachine
from .tiers import EVIDENCE_TIER_ORDER, EvidenceTier, tier_rank

__all__ = [
    "EVIDENCE_TIER_ORDER",
    "EvidenceStateMachine",
    "EvidenceTier",
    "can_unlock_destructive_remediation",
    "tier_rank",
    "validate_tier_upgrade",
]
