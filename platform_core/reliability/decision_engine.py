"""Orchestrate the full reliability platform decision pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from platform_core.reasoning_models import new_id

from .audit_integrity import sign_decision_record
from .event_pipeline import EventPipeline, normalize_raw_observation
from .evidence_graph import build_evidence_graph
from .hypothesis_engine import rank_hypotheses
from .models import NormalizedPlatformEvent, PlatformDecisionRecord
from .platform_states import transition_platform_state
from .policy_config import PolicyConfig, evaluate_platform_policy


def run_platform_decision(
    observations: list[dict[str, Any]],
    *,
    endpoint_id: str = "local",
    requested_action: str | None = None,
    explicit_confirmation: bool = False,
    context: dict[str, Any] | None = None,
    policy: PolicyConfig | None = None,
    run_id: str | None = None,
    signing_secret: str | None = None,
) -> PlatformDecisionRecord:
    """Full pipeline: Observation → Event → State → Hypothesis → Evidence → Policy → Decision."""
    rid = run_id or new_id("run")
    events: list[NormalizedPlatformEvent] = [
        normalize_raw_observation(obs, endpoint_id=endpoint_id) for obs in observations
    ]
    transitions, state_path = transition_platform_state(events, endpoint_id=endpoint_id)
    graph = build_evidence_graph(events, transitions, process_snapshot=(context or {}).get("process_snapshot"))
    ranking = rank_hypotheses(events, context=context)
    accepted = ranking[0] if ranking else None
    has_proof = any(e.evidence_tier == "TIER_3_CAUSAL_PROOF" for e in events)
    outcome, reason_codes = evaluate_platform_policy(
        hypothesis=accepted,
        policy=policy,
        requested_action=requested_action,
        has_proof_tier=has_proof,
        explicit_confirmation=explicit_confirmation,
    )
    limitations = [
        "Observation != Proof; correlation != causation; confidence != certainty.",
        "Ordinal confidence scores are not calibrated probabilities.",
    ]
    if not has_proof:
        limitations.append("No proof-tier evidence; registry writer not established.")

    record = PlatformDecisionRecord(
        run_id=rid,
        endpoint_id=endpoint_id,
        state_path=[s.value if hasattr(s, "value") else str(s) for s in state_path],
        accepted_hypothesis=accepted.label if accepted else "",
        hypothesis_ranking=[h.model_dump(mode="json") for h in ranking],
        policy_outcome=outcome,
        policy_reason_codes=reason_codes,
        evidence_graph_summary=graph.to_jsonable(),
        event_ids=[e.event_id for e in events],
        limitations=limitations,
    )
    record = sign_decision_record(record, secret=signing_secret)
    return record


def persist_decision(
    record: PlatformDecisionRecord,
    *,
    events: list[NormalizedPlatformEvent],
    pipeline: EventPipeline | None = None,
) -> None:
    """Append events + decision to append-only stores."""
    pipe = pipeline or EventPipeline()
    for ev in events:
        pipe.append(ev)
        try:
            from platform_core.db.postgres import append_event_pg

            append_event_pg(ev)
        except Exception:
            pass
    from platform_core import storage

    storage.append_jsonl(storage.platform_data_dir() / "platform_decisions.jsonl", record.model_dump(mode="json"))
    try:
        from platform_core.db.postgres import append_decision_pg

        append_decision_pg(record)
    except Exception:
        pass


def replay_decision(run_id: str, *, path: Path | None = None):
    """Time-travel replay for a stored run_id."""
    from .time_travel import TimeTravelReplay

    return TimeTravelReplay.load_and_replay(run_id, path=path)
