"""Event correlation engine: Observation → Event → State → Confidence → Evidence Tree."""

from __future__ import annotations

from typing import Any

from platform_core.reasoning_engine import observation, run_reasoning
from platform_core.reasoning_models import Observation, ProofResult, ReasoningRun


def observations_from_signals(rows: list[dict[str, Any]]) -> list[Observation]:
    """Convert API/agent signal dicts into typed observations."""
    out: list[Observation] = []
    for row in rows:
        name = str(row.get("signal_name") or row.get("name") or "")
        if not name:
            continue
        value = row.get("value")
        if isinstance(value, dict):
            continue
        out.append(
            observation(
                name,
                value,
                source=str(row.get("source") or "api"),
            )
        )
    return out


def _confidence_from_run(run: ReasoningRun) -> float:
    if run.hypothesis_ranking:
        top = run.hypothesis_ranking[0]
        score = top.get("score")
        if isinstance(score, (int, float)):
            return float(score)
    if run.detected_events:
        return float(run.detected_events[0].confidence)
    return 0.0


def correlate(
    *,
    signals: list[dict[str, Any]],
    requested_action: str = "inspect_proxy",
    proof_result: ProofResult | None = None,
    endpoint_id: str = "local",
) -> dict[str, Any]:
    """Run full correlation pipeline and return dashboard-friendly JSON."""
    obs = observations_from_signals(signals)
    proof = proof_result or ProofResult(hypothesis="", status="NOT_RUN", checks_run=[])
    run: ReasoningRun = run_reasoning(
        obs,
        proof_result=proof,
        requested_action=requested_action,
    )
    confidence = _confidence_from_run(run)
    return {
        "correlation_id": run.id,
        "endpoint_id": endpoint_id,
        "observations": [o.model_dump(mode="json") for o in run.raw_observations],
        "events": [e.model_dump(mode="json") for e in run.detected_events],
        "state_transitions": [s.model_dump(mode="json") for s in run.state_transitions],
        "confidence_score": confidence,
        "confidence_note": "Ordinal ranking score, not calibrated probability.",
        "hypothesis_ranking": run.hypothesis_ranking,
        "accepted_hypothesis": run.accepted_hypothesis,
        "evidence_tree": run.evidence_tree.model_dump(mode="json"),
        "policy_decision": run.policy_decision.model_dump(mode="json"),
        "reliability_impact": run.reliability_impact.model_dump(mode="json"),
        "remediation_preview": run.remediation_preview,
        "limitations": run.limitations,
        "recommended_next_steps": run.recommended_next_steps,
        "replayable": True,
        "dry_run_only": run.policy_decision.outcome != "ALLOW",
    }


def correlate_from_probe(*, endpoint_id: str = "local") -> dict[str, Any]:
    """Correlate using platform OS probe observations only."""
    from platform_core.os_probe import collect_platform_observations

    probe = collect_platform_observations()
    return correlate(signals=list(probe.get("observations") or []), endpoint_id=endpoint_id)
