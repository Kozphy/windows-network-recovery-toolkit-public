"""Governance package interfaces for audit-aware control reporting.

Module responsibility:
    Expose package-level interfaces without performing runtime work.

System placement:
    Imported by platform modules that need the package namespace.

Key invariants:
    Importing this package must not collect evidence or mutate state.

Side effects:
    None.
"""

from .chain_of_custody import chain_hash, verify_chain
from .control_mapping import map_policy_outcome_to_controls
from .evidence_decision_lifecycle import (
    Claim,
    ClaimStatus,
    EvidenceDecisionLifecycle,
    KnowledgeRecord,
    UncertaintyAssessment,
    VerificationResult,
    VerificationStatus,
    lifecycle_from_risk_decision,
)
from .evidence_to_action import (
    GOVERNANCE_MODEL,
    attach_governance_envelope,
    build_governance_envelope,
    causal_language_allowed,
    narrative_passes_governance_language,
)
from .policy_compiler import compile_policy_matrix

__all__ = [
    "Claim",
    "ClaimStatus",
    "EvidenceDecisionLifecycle",
    "GOVERNANCE_MODEL",
    "KnowledgeRecord",
    "UncertaintyAssessment",
    "VerificationResult",
    "VerificationStatus",
    "attach_governance_envelope",
    "build_governance_envelope",
    "causal_language_allowed",
    "chain_hash",
    "compile_policy_matrix",
    "lifecycle_from_risk_decision",
    "map_policy_outcome_to_controls",
    "narrative_passes_governance_language",
    "verify_chain",
]
