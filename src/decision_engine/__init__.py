"""Decision engine — v1 root-cause scoring and generic decision intelligence scoring."""

from .counterfactual import (
    CounterfactualAlternative,
    CounterfactualSimulationResult,
    SimulationAssumption,
    counterfactual_payload,
    global_assumptions,
    simulate_counterfactuals,
    simulate_decision_paths,
    verify_simulation_determinism,
)
from .decision_engine import (
    DecisionEngineResult,
    content_digest,
    engine_summary,
    run_decision_engine,
)
from .ranking import RankedDecision, rank_scored_decisions, top_ranked
from .scoring import (
    ALL_CAUSES,
    CandidateDecision,
    DecisionResult,
    EvidenceItem,
    RootCauseKey,
    ScoreBreakdown,
    ScoredDecision,
    explain_primary,
    score_candidate,
    score_candidates,
    score_root_causes,
    scored_to_payload,
)

__all__ = [
    "ALL_CAUSES",
    "CandidateDecision",
    "CounterfactualAlternative",
    "CounterfactualSimulationResult",
    "DecisionEngineResult",
    "SimulationAssumption",
    "counterfactual_payload",
    "global_assumptions",
    "simulate_counterfactuals",
    "simulate_decision_paths",
    "verify_simulation_determinism",
    "DecisionResult",
    "EvidenceItem",
    "RankedDecision",
    "RootCauseKey",
    "ScoreBreakdown",
    "ScoredDecision",
    "content_digest",
    "engine_summary",
    "explain_primary",
    "rank_scored_decisions",
    "run_decision_engine",
    "score_candidate",
    "score_candidates",
    "score_root_causes",
    "scored_to_payload",
    "top_ranked",
]
