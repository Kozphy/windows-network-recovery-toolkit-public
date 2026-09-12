"""Versioned API v2 — production reliability platform endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.platform_auth import get_platform_principal
from backend.prometheus_exporter import inc as prom_inc
from backend.tracing import span
from platform_core.db.postgres import append_event_pg, is_postgres_configured
from platform_core.rbac import DemoPrincipal, assert_can_preview, assert_can_read_metrics
from platform_core.reliability.audit_integrity import verify_decision_record
from platform_core.reliability.decision_engine import (
    persist_decision,
    replay_decision,
    run_platform_decision,
)
from platform_core.reliability.event_pipeline import EventPipeline
from platform_core.reliability.models import PlatformDecisionRecord
from platform_core.reliability.policy_config import PolicyConfig

router = APIRouter(prefix="/v2", tags=["platform-v2"])


class DecisionRunRequest(BaseModel):
    """Represent decision run request data used by the toolkit.
    
    Attributes:
        endpoint_id: Field or variant describing endpoint id evidence or state.
        observations: Field or variant describing observations evidence or state.
        requested_action: Field or variant describing requested action evidence or state.
        explicit_confirmation: Field or variant describing explicit confirmation evidence or state.
        context: Field or variant describing context evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    endpoint_id: str = "local"
    observations: list[dict[str, Any]]
    requested_action: str | None = None
    explicit_confirmation: bool = False
    context: dict[str, Any] = Field(default_factory=dict)


class EventIngestRequest(BaseModel):
    """Represent event ingest request data used by the toolkit.
    
    Attributes:
        endpoint_id: Field or variant describing endpoint id evidence or state.
        events: Field or variant describing events evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    endpoint_id: str = "local"
    events: list[dict[str, Any]]


@router.get("/health")
def v2_health() -> dict[str, Any]:
    """Handle the GET request for v2 health.
    
    Args:
        None.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    return {
        "status": "ok",
        "api_version": "v2",
        "postgres_configured": is_postgres_configured(),
        "principles": [
            "observation_ne_proof",
            "correlation_ne_causation",
            "confidence_ne_certainty",
        ],
    }


@router.post("/events/ingest")
def ingest_events(
    body: EventIngestRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for ingest events.
    
    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    with span("v2.events.ingest", endpoint_id=body.endpoint_id):
        pipe = EventPipeline()
        ingested = pipe.ingest_batch(body.events, endpoint_id=body.endpoint_id)
        for ev in ingested:
            append_event_pg(ev)
        prom_inc("platform_event_ingest_total")
        return {"ingested": len(ingested), "event_ids": [e.event_id for e in ingested]}


@router.post("/decisions/run")
def run_decision(
    body: DecisionRunRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Full pipeline: normalize → state → hypothesis → evidence graph → policy."""
    assert_can_preview(principal)
    policy = PolicyConfig.from_yaml_path(Path("config/platform_policy.yaml"))
    with span("v2.decisions.run", endpoint_id=body.endpoint_id):
        record = run_platform_decision(
            body.observations,
            endpoint_id=body.endpoint_id,
            requested_action=body.requested_action,
            explicit_confirmation=body.explicit_confirmation,
            context=body.context,
            policy=policy,
        )
        from platform_core.reliability.event_pipeline import normalize_raw_observation

        events = [
            normalize_raw_observation(o, endpoint_id=body.endpoint_id).model_copy(
                update={"event_id": eid}
            )
            for o, eid in zip(body.observations, record.event_ids, strict=False)
        ]
        persist_decision(record, events=events)
        if record.policy_outcome == "BLOCK":
            prom_inc("platform_policy_blocked_total")
        elif record.policy_outcome == "ALLOW":
            prom_inc("platform_policy_allow_total")
        else:
            prom_inc("platform_policy_preview_total")
        prom_inc("platform_decision_runs_total")
        return record.model_dump(mode="json")


@router.get("/decisions/replay/{run_id}")
def replay_decision_route(
    run_id: str,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for replay decision route.
    
    Args:
        run_id: The run id value supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    assert_can_preview(principal)
    with span("v2.decisions.replay", run_id=run_id):
        try:
            result = replay_decision(run_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"run_id {run_id} not found") from None
        return result.to_jsonable()


@router.get("/events")
def list_events(
    limit: int = 50,
    endpoint_id: str | None = None,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for list events.
    
    Args:
        limit: The limit value supplied by the caller.
        endpoint_id: The endpoint id value supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    pipe = EventPipeline()
    items = [e.model_dump(mode="json") for e in pipe.iter_events(endpoint_id=endpoint_id, limit=limit)]
    return {"items": items, "count": len(items)}


@router.get("/policies/summary")
def policy_summary(
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for policy summary.
    
    Args:
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    assert_can_read_metrics(principal)
    cfg = PolicyConfig.from_yaml_path(Path("config/platform_policy.yaml"))
    return {
        "safe_mode": cfg.safe_mode,
        "default_outcome": cfg.default_outcome,
        "rules": [
            {
                "rule_id": r.rule_id,
                "outcome": r.outcome,
                "min_confidence": r.min_confidence,
                "requires_proof_tier": r.requires_proof_tier,
            }
            for r in cfg.rules
        ],
    }


@router.post("/audit/verify")
def verify_audit(
    body: dict[str, Any],
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for verify audit.
    
    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    assert_can_read_metrics(principal)
    try:
        rec = PlatformDecisionRecord(**body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    ok, reason = verify_decision_record(rec)
    return {"valid": ok, "reason": reason, "run_id": rec.run_id}
