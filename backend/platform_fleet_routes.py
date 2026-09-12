"""Fleet-scale API v3 — distributed ingest, replay jobs, tenant-scoped operations."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from backend.platform_auth import get_platform_principal
from backend.prometheus_exporter import inc_labeled
from backend.tracing import span
from platform_core.fleet.ingestion import FleetIngestGateway
from platform_core.fleet.models import FleetEventEnvelope
from platform_core.fleet.observability import ingest_result_to_labels
from platform_core.fleet.partitioning import assign_partition
from platform_core.fleet.replay import ReplayCoordinator, ReplayJobSpec
from platform_core.fleet.tenancy import TenantPrincipal, assert_tenant_access
from platform_core.rbac import DemoPrincipal, assert_can_preview

router = APIRouter(prefix="/v3/fleet", tags=["platform-fleet"])

_gateway = FleetIngestGateway()
_replay = ReplayCoordinator()


class IngestBatchRequest(BaseModel):
    """Represent ingest batch request data used by the toolkit.
    
    Attributes:
        tenant_id: Field or variant describing tenant id evidence or state.
        events: Field or variant describing events evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    tenant_id: str
    events: list[FleetEventEnvelope]


class ReplayJobRequest(BaseModel):
    """Represent replay job request data used by the toolkit.
    
    Attributes:
        tenant_id: Field or variant describing tenant id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        time_start_utc: Field or variant describing time start utc evidence or state.
        time_end_utc: Field or variant describing time end utc evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    tenant_id: str
    incident_id: str
    time_start_utc: str
    time_end_utc: str


def _demo_to_tenant_principal(demo: DemoPrincipal, tenant_id: str) -> TenantPrincipal:
    role_map = {
        "viewer": "tenant_viewer",
        "operator": "tenant_operator",
        "admin": "tenant_admin",
        "security_auditor": "tenant_security_auditor",
    }
    return TenantPrincipal(
        subject=demo.operator_id,
        tenant_id=tenant_id,
        roles=frozenset({role_map.get(demo.role, "tenant_operator")}),
    )


@router.get("/health")
def fleet_health() -> dict[str, Any]:
    """Handle the GET request for fleet health.
    
    Args:
        None.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    return {
        "status": "ok",
        "api_version": "v3-fleet",
        "partition_count": assign_partition("health", "0" * 32).partition_total,
        "capabilities": [
            "distributed_ingest",
            "idempotency_dedup",
            "partition_assignment",
            "partition_replay_jobs",
        ],
    }


@router.post("/ingest/batch")
def ingest_batch(
    body: IngestBatchRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    """Distributed ingestion with deduplication (gateway contract)."""
    assert_can_preview(principal)
    tp = _demo_to_tenant_principal(principal, body.tenant_id)
    assert_tenant_access(tp, body.tenant_id, action="write")

    with span("fleet.ingest.batch", tenant_id=body.tenant_id, count=len(body.events)):
        results = []
        for raw in body.events:
            if raw.tenant.tenant_id != body.tenant_id:
                raise HTTPException(status_code=400, detail="tenant_id_mismatch_in_envelope")
            if idempotency_key and not raw.idempotency_key:
                raw = raw.model_copy(update={"idempotency_key": idempotency_key})
            result = _gateway.ingest_one(raw)
            labels = ingest_result_to_labels(
                body.tenant_id, result.partition_id, result.dedup.outcome
            )
            inc_labeled(f"fleet_ingest_{result.dedup.outcome}_total", labels)
            results.append(
                {
                    "event_id": result.event_id,
                    "accepted": result.accepted,
                    "partition_id": result.partition_id,
                    "topic": result.topic,
                    "dedup_outcome": result.dedup.outcome,
                    "published": result.published,
                }
            )
        return {"tenant_id": body.tenant_id, "results": results, "count": len(results)}


@router.post("/replay/jobs")
def enqueue_replay(
    body: ReplayJobRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for enqueue replay.
    
    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    tp = _demo_to_tenant_principal(principal, body.tenant_id)
    assert_tenant_access(tp, body.tenant_id, action="replay")

    part = assign_partition(body.tenant_id, body.incident_id[:32].ljust(32, "0"))
    from platform_core.reasoning_models import new_id

    spec = ReplayJobSpec.for_incident(
        job_id=new_id("replay"),
        tenant_id=body.tenant_id,
        incident_id=body.incident_id,
        partition_id=part.partition_id,
        time_start_utc=body.time_start_utc,
        time_end_utc=body.time_end_utc,
    )
    _replay.enqueue(spec)
    result = _replay.run_local(spec)
    return {"job_id": spec.job_id, "spec": spec.__dict__, "result": result.__dict__}


@router.get("/replay/jobs/{job_id}")
def get_replay_job(
    job_id: str,
    tenant_id: str,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for get replay job.
    
    Args:
        job_id: The job id value supplied by the caller.
        tenant_id: The tenant id value supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    tp = _demo_to_tenant_principal(principal, tenant_id)
    assert_tenant_access(tp, tenant_id, action="replay")
    result = _replay.get_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="replay job not found")
    return result.__dict__
