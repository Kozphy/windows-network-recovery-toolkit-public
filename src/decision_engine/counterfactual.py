"""Counterfactual simulation — compare Decision A / B / C without machine learning.

Pipeline:
    Shared Evidence → simulate each candidate → expected benefit / risk / confidence
    → rank → chosen decision + alternatives

Every score is derived from explicit constants and documented assumptions.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .decision_engine import content_digest
from .ranking import rank_scored_decisions
from .scoring import (
    BENEFIT_EVIDENCE_SCALE,
    CONFIDENCE_FORMULA,
    FINAL_SCORE_FORMULA,
    RISK_EVIDENCE_SCALE,
    CandidateDecision,
    EvidenceItem,
    score_candidates,
)


class SimulationAssumption(BaseModel):
    """One explicit assumption used by the counterfactual simulator."""

    assumption_id: str
    statement: str
    scope: str = "global"  # global | decision | evidence


class CounterfactualAlternative(BaseModel):
    """Simulated path for a non-chosen decision."""

    decision: str
    decision_id: str
    expected_benefit: int = Field(ge=0, le=100)
    expected_risk: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    final_score: int = Field(ge=0, le=100)
    rank: int = Field(ge=1)
    assumptions: list[SimulationAssumption] = Field(default_factory=list)


class CounterfactualSimulationResult(BaseModel):
    """Output of a deterministic counterfactual run."""

    chosen_decision: str
    chosen_decision_id: str
    expected_benefit: int = Field(ge=0, le=100)
    expected_risk: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    final_score: int = Field(ge=0, le=100)
    alternatives: list[CounterfactualAlternative] = Field(default_factory=list)
    assumptions: list[SimulationAssumption] = Field(default_factory=list)
    content_digest: str = ""


def global_assumptions() -> list[SimulationAssumption]:
    """Assumptions that apply to every counterfactual simulation."""
    return [
        SimulationAssumption(
            assumption_id="no_ml",
            statement="No machine learning — all estimates are rule-based transforms of input evidence.",
            scope="global",
        ),
        SimulationAssumption(
            assumption_id="ordinal_scores",
            statement="Benefit, risk, and confidence are ordinal research estimates, not calibrated probabilities.",
            scope="global",
        ),
        SimulationAssumption(
            assumption_id="shared_evidence",
            statement="All candidates are evaluated against the same frozen evidence snapshot.",
            scope="global",
        ),
        SimulationAssumption(
            assumption_id="benefit_scale",
            statement=f"Supporting evidence contributes weight × relevance × {BENEFIT_EVIDENCE_SCALE} to benefit.",
            scope="global",
        ),
        SimulationAssumption(
            assumption_id="risk_scale",
            statement=f"Contradicting evidence contributes weight × relevance × {RISK_EVIDENCE_SCALE} to risk.",
            scope="global",
        ),
        SimulationAssumption(
            assumption_id="confidence_formula",
            statement=CONFIDENCE_FORMULA,
            scope="global",
        ),
        SimulationAssumption(
            assumption_id="final_score_formula",
            statement=FINAL_SCORE_FORMULA,
            scope="global",
        ),
        SimulationAssumption(
            assumption_id="ranking_policy",
            statement="Chosen decision = highest final_score; ties broken by confidence then decision_id.",
            scope="global",
        ),
    ]


def _decision_assumptions(
    candidate: CandidateDecision,
    evidence: list[EvidenceItem],
) -> list[SimulationAssumption]:
    assumptions = [
        SimulationAssumption(
            assumption_id=f"{candidate.decision_id}:base_benefit",
            statement=f"Counterfactual '{candidate.label}' assumes base benefit {candidate.base_benefit}.",
            scope="decision",
        ),
        SimulationAssumption(
            assumption_id=f"{candidate.decision_id}:base_risk",
            statement=f"Counterfactual '{candidate.label}' assumes base risk {candidate.base_risk}.",
            scope="decision",
        ),
    ]
    if candidate.evidence_relevance:
        assumptions.append(
            SimulationAssumption(
                assumption_id=f"{candidate.decision_id}:relevance_map",
                statement=(
                    f"Evidence relevance map for '{candidate.label}': "
                    f"{dict(sorted(candidate.evidence_relevance.items()))}."
                ),
                scope="decision",
            )
        )
    else:
        assumptions.append(
            SimulationAssumption(
                assumption_id=f"{candidate.decision_id}:full_evidence",
                statement=f"All evidence items apply at relevance 1.0 to '{candidate.label}'.",
                scope="decision",
            )
        )
    for name, value in sorted(candidate.risk_factors.items()):
        assumptions.append(
            SimulationAssumption(
                assumption_id=f"{candidate.decision_id}:risk_factor:{name}",
                statement=f"Risk factor '{name}' adds {value} to expected risk for '{candidate.label}'.",
                scope="decision",
            )
        )
    relevance = candidate.evidence_relevance or {item.evidence_id: 1.0 for item in evidence}
    for item in evidence:
        rel = float(relevance.get(item.evidence_id, 0.0) if candidate.evidence_relevance else 1.0)
        if rel <= 0:
            continue
        assumptions.append(
            SimulationAssumption(
                assumption_id=f"{candidate.decision_id}:evidence:{item.evidence_id}",
                statement=(
                    f"Evidence '{item.label}' (weight={item.weight}, supports={item.supports_decision}, "
                    f"relevance={rel}) is included in the simulation for '{candidate.label}'."
                ),
                scope="evidence",
            )
        )
    return assumptions


def simulate_counterfactuals(
    evidence: list[EvidenceItem],
    candidates: list[CandidateDecision],
) -> CounterfactualSimulationResult:
    """Simulate Decision A / B / C (or more) and return chosen path + alternatives."""
    if len(candidates) < 2:
        raise ValueError("counterfactual simulation requires at least two candidate decisions")

    scored = score_candidates(evidence, candidates)
    ranked = rank_scored_decisions(scored)
    chosen = ranked[0]

    chosen_assumptions = _decision_assumptions(
        next(c for c in candidates if c.decision_id == chosen.decision_id),
        evidence,
    )

    alternatives: list[CounterfactualAlternative] = []
    for row in ranked[1:]:
        candidate = next(c for c in candidates if c.decision_id == row.decision_id)
        alternatives.append(
            CounterfactualAlternative(
                decision=row.decision,
                decision_id=row.decision_id,
                expected_benefit=row.benefit,
                expected_risk=row.risk,
                confidence=row.confidence,
                final_score=row.final_score,
                rank=row.rank,
                assumptions=_decision_assumptions(candidate, evidence),
            )
        )

    payload = counterfactual_payload(
        CounterfactualSimulationResult(
            chosen_decision=chosen.decision,
            chosen_decision_id=chosen.decision_id,
            expected_benefit=chosen.benefit,
            expected_risk=chosen.risk,
            confidence=chosen.confidence,
            final_score=chosen.final_score,
            alternatives=alternatives,
            assumptions=global_assumptions() + chosen_assumptions,
        )
    )
    digest = content_digest(payload)

    return CounterfactualSimulationResult(
        chosen_decision=chosen.decision,
        chosen_decision_id=chosen.decision_id,
        expected_benefit=chosen.benefit,
        expected_risk=chosen.risk,
        confidence=chosen.confidence,
        final_score=chosen.final_score,
        alternatives=alternatives,
        assumptions=global_assumptions() + chosen_assumptions,
        content_digest=digest,
    )


def counterfactual_payload(result: CounterfactualSimulationResult) -> dict[str, Any]:
    """Primary API output contract."""
    return {
        "chosen_decision": result.chosen_decision,
        "chosen_decision_id": result.chosen_decision_id,
        "expected_benefit": result.expected_benefit,
        "expected_risk": result.expected_risk,
        "confidence": result.confidence,
        "final_score": result.final_score,
        "alternatives": [
            {
                "decision": alt.decision,
                "decision_id": alt.decision_id,
                "expected_benefit": alt.expected_benefit,
                "expected_risk": alt.expected_risk,
                "confidence": alt.confidence,
                "final_score": alt.final_score,
                "rank": alt.rank,
                "assumptions": [a.model_dump(mode="json") for a in alt.assumptions],
            }
            for alt in result.alternatives
        ],
        "assumptions": [a.model_dump(mode="json") for a in result.assumptions],
        "content_digest": result.content_digest,
    }


def simulate_decision_paths(
    evidence: list[EvidenceItem],
    decision_a: CandidateDecision,
    decision_b: CandidateDecision,
    decision_c: CandidateDecision | None = None,
    extra: list[CandidateDecision] | None = None,
) -> CounterfactualSimulationResult:
    """Convenience wrapper for Decision A / B / C counterfactual comparison."""
    candidates = [decision_a, decision_b]
    if decision_c is not None:
        candidates.append(decision_c)
    if extra:
        candidates.extend(extra)
    return simulate_counterfactuals(evidence, candidates)


def verify_simulation_determinism(
    evidence: list[EvidenceItem],
    candidates: list[CandidateDecision],
) -> tuple[bool, str, str]:
    """Return (deterministic, digest_a, digest_b) for replay tests."""
    first = simulate_counterfactuals(evidence, candidates)
    second = simulate_counterfactuals(evidence, candidates)
    return first.content_digest == second.content_digest, first.content_digest, second.content_digest
