"""Unified Multi-Domain Decision Platform API routes.

Mounted under ``/platform/decision/*`` to avoid conflicting with endpoint-reliability
``/platform/events`` (normalized_events.jsonl) and ``/platform/metrics`` (SLO JSONL).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from backend.platform_auth import get_platform_principal
from platform_core.rbac import DemoPrincipal, assert_can_preview, assert_can_read_metrics
from src.platform.audit import read_audit_tail
from src.platform.models import DecisionOutcome
from src.platform.outcome_engine import compute_metrics, metrics_to_dict
from src.platform.registry import all_adapters, get_adapter
from src.platform.replay import find_event, replay_all, run_pipeline

router = APIRouter(prefix="/platform/decision", tags=["platform-decision"])


class OutcomeIn(BaseModel):
    """Represent outcome in data used by the toolkit.

    Attributes:
        decision_id: Field or variant describing decision id evidence or state.
        success: Field or variant describing success evidence or state.
        observed_result: Field or variant describing observed result evidence or state.
        cost_score: Field or variant describing cost score evidence or state.
        time_to_resolution_seconds: Field or variant describing time to resolution seconds evidence or state.
        lessons_learned: Field or variant describing lessons learned evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    decision_id: str
    success: bool = True
    observed_result: str = ""
    cost_score: float = Field(default=0.1, ge=0.0, le=1.0)
    time_to_resolution_seconds: float = Field(default=120.0, ge=0.0)
    lessons_learned: str = ""


@router.get("/events")
def list_mdp_events(
    domain: str | None = None,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for list mdp events.

    Args:
        domain: The domain value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    adapters = [get_adapter(domain)] if domain else all_adapters()
    events = []
    for adapter in adapters:
        for fname in adapter.list_fixtures():
            events.extend(ev.model_dump(mode="json") for ev in adapter.collect_events(fname))
    return {"items": events, "count": len(events)}


@router.get("/evidence")
def get_evidence(
    event_id: str = Query(...),
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for get evidence.

    Args:
        event_id: The event id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    try:
        adapter, fname = find_event(event_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    result = run_pipeline(adapter, fixture_name=fname, record_audit=False)
    return {
        "event_id": event_id,
        "confidence_score": result.evidence_result.confidence_score,
        "ranked_hypotheses": [
            h.model_dump(mode="json") for h in result.evidence_result.ranked_hypotheses
        ],
        "evidence_tree": [e.model_dump(mode="json") for e in result.evidence],
        "explanation": result.evidence_result.explanation,
    }


@router.get("/decisions")
def get_decisions(
    event_id: str = Query(...),
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for get decisions.

    Args:
        event_id: The event id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    assert_can_preview(principal)
    try:
        adapter, fname = find_event(event_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    result = run_pipeline(adapter, fixture_name=fname, command="decide")
    return {
        "event_id": event_id,
        "fingerprint": result.fingerprint,
        "top_decision": result.top_decision.model_dump(mode="json")
        if result.top_decision
        else None,
        "ranked_decisions": [
            {"decision": r.decision.model_dump(mode="json"), "final_score": r.final_score}
            for r in result.ranked_decisions
        ],
    }


@router.post("/outcomes")
def post_outcome(
    body: OutcomeIn,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for post outcome.

    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    outcome = DecisionOutcome(
        outcome_id=f"out-{body.decision_id}",
        decision_id=body.decision_id,
        success=body.success,
        observed_result=body.observed_result,
        cost_score=body.cost_score,
        time_to_resolution_seconds=body.time_to_resolution_seconds,
        lessons_learned=body.lessons_learned,
    )
    return outcome.model_dump(mode="json")


@router.post("/replay")
def post_replay(
    domain: str | None = None,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for post replay.

    Args:
        domain: The domain value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    if domain:
        adapter = get_adapter(domain)
        results = [
            run_pipeline(adapter, fixture_name=f, command="replay") for f in adapter.list_fixtures()
        ]
    else:
        results = replay_all()
    return {
        "replayed": len(results),
        "fingerprints": [r.fingerprint for r in results],
        "events": [r.event.event_id for r in results],
    }


@router.get("/metrics")
def get_mdp_metrics(
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for get mdp metrics.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    decisions_by_id = {}
    domain_by_decision = {}
    for adapter in all_adapters():
        for fname in adapter.list_fixtures():
            result = run_pipeline(adapter, fixture_name=fname, record_audit=False)
            for r in result.ranked_decisions:
                decisions_by_id[r.decision.decision_id] = r.decision
                domain_by_decision[r.decision.decision_id] = result.event.domain
    metrics = compute_metrics([], decisions_by_id, domain_by_decision=domain_by_decision)
    return {
        "outcome_metrics": metrics_to_dict(metrics),
        "audit_tail": len(read_audit_tail(limit=50)),
        "fixture_count": sum(len(a.list_fixtures()) for a in all_adapters()),
    }
