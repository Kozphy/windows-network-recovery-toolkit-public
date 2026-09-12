"""Event-state reasoning public API (models + epistemic helpers).

Re-exports :mod:`platform_core.reasoning_models` and :mod:`platform_core.reasoning_engine`
so portfolio docs can reference ``platform_core.reasoning`` as the architecture layer.
"""

from platform_core.reasoning.layers import (
    EpistemicLayer,
    cap_conclusion_strength,
    evidence_level_for_layer,
)
from platform_core.reasoning_engine import (
    DESTRUCTIVE_ACTION_TOKENS,
    SAFE_REGISTRY_ACTIONS,
    evaluate_reasoning_policy,
    observation,
    run_reasoning,
)
from platform_core.reasoning_models import (
    AuditMetadata,
    EndpointEvent,
    EndpointState,
    EvidenceLevel,
    EvidenceNode,
    EvidenceTree,
    FailureScenario,
    Observation,
    PolicyDecision,
    PolicyOutcome,
    ProofResult,
    ProofStatus,
    ReasoningRun,
    ReliabilityImpact,
    StateTransition,
    new_id,
)

# Alias: ranked hypothesis rows in ReasoningRun use this shape.
Hypothesis = dict

AuditRecord = dict

__all__ = [
    "AuditMetadata",
    "AuditRecord",
    "DESTRUCTIVE_ACTION_TOKENS",
    "EndpointEvent",
    "EndpointState",
    "EpistemicLayer",
    "EvidenceLevel",
    "EvidenceNode",
    "EvidenceTree",
    "FailureScenario",
    "Hypothesis",
    "Observation",
    "PolicyDecision",
    "PolicyOutcome",
    "ProofResult",
    "ProofStatus",
    "ReasoningRun",
    "ReliabilityImpact",
    "SAFE_REGISTRY_ACTIONS",
    "StateTransition",
    "cap_conclusion_strength",
    "evaluate_reasoning_policy",
    "evidence_level_for_layer",
    "new_id",
    "observation",
    "run_reasoning",
]
