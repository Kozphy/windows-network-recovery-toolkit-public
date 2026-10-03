"""SRE operations API — incidents, investigation, timeline, RCA, postmortems, MTTR."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.platform_auth import get_platform_principal
from backend.prometheus_exporter import inc as prom_inc
from backend.tracing import span
from platform_core.rbac import DemoPrincipal, assert_can_preview, assert_can_read_metrics
from platform_core.sre.failure_domains import get_domain_health
from platform_core.sre.incident_aggregate import IncidentAggregate
from platform_core.sre.investigation import run_investigation
from platform_core.sre.mttr import compute_incident_mttr_metrics, mttr_metrics_for_prometheus
from platform_core.sre.postmortem import generate_postmortem
from platform_core.sre.projector import list_incident_ids, rebuild_incident
from platform_core.sre.rca import build_rca_report
from platform_core.sre.timeline import reconstruct_timeline

router = APIRouter(prefix="/v2/sre", tags=["platform-sre"])


class OpenIncidentRequest(BaseModel):
    """Represent open incident request data used by the toolkit.

    Attributes:
        endpoint_id: Field or variant describing endpoint id evidence or state.
        title: Field or variant describing title evidence or state.
        severity: Field or variant describing severity evidence or state.
        trigger_event_ids: Field or variant describing trigger event ids evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    endpoint_id: str
    title: str
    severity: str = "medium"
    trigger_event_ids: list[str] = Field(default_factory=list)


class InvestigateRequest(BaseModel):
    """Represent investigate request data used by the toolkit.

    Attributes:
        observations: Field or variant describing observations evidence or state.
        endpoint_id: Field or variant describing endpoint id evidence or state.
        context: Field or variant describing context evidence or state.
        requested_action: Field or variant describing requested action evidence or state.
        explicit_confirmation: Field or variant describing explicit confirmation evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    observations: list[dict[str, Any]]
    endpoint_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    requested_action: str | None = None
    explicit_confirmation: bool = False


class ResolveIncidentRequest(BaseModel):
    """Represent resolve incident request data used by the toolkit.

    Attributes:
        resolution: Field or variant describing resolution evidence or state.
        actor: Field or variant describing actor evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    resolution: str
    actor: str = "operator"


class MitigationRequest(BaseModel):
    """Represent mitigation request data used by the toolkit.

    Attributes:
        action: Field or variant describing action evidence or state.
        outcome: Field or variant describing outcome evidence or state.
        actor: Field or variant describing actor evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    action: str
    outcome: str
    actor: str = "operator"


@router.get("/health")
def sre_health() -> dict[str, Any]:
    """Handle the GET request for sre health.

    Args:
        None.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    domains = get_domain_health()
    return {
        "status": "ok",
        "failure_domains": [
            {
                "domain": d.domain.value,
                "state": d.state,
                "degraded": d.degraded,
                "failure_count": d.failure_count,
                "message": d.message,
            }
            for d in domains
        ],
        "principles": [
            "event_sourced_incidents",
            "deterministic_projections",
            "failure_domain_isolation",
            "observation_ne_proof",
        ],
    }


@router.get("/metrics/mttr")
def sre_mttr_metrics(
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for sre mttr metrics.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    metrics = compute_incident_mttr_metrics()
    return {
        "metrics": metrics.model_dump(mode="json"),
        "prometheus_gauges": mttr_metrics_for_prometheus(metrics),
    }


@router.post("/incidents")
def open_incident(
    body: OpenIncidentRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for open incident.

    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    with span("sre.incident.open", endpoint_id=body.endpoint_id):
        agg = IncidentAggregate.open(
            endpoint_id=body.endpoint_id,
            title=body.title,
            severity=body.severity,
            trigger_event_ids=body.trigger_event_ids,
        )
        prom_inc("platform_sre_incident_opened_total")
        proj = agg.projection
        return {
            "incident_id": agg.incident_id,
            "phase": proj.phase.value,
            "detected_at": proj.detected_at,
        }


@router.get("/incidents")
def list_incidents(
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for list incidents.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    items = []
    for iid in list_incident_ids():
        proj = rebuild_incident(iid)
        items.append(proj.model_dump(mode="json"))
    return {"items": items, "count": len(items)}


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for get incident.

    Args:
        incident_id: The incident id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    proj = rebuild_incident(incident_id)
    if proj.event_count == 0:
        raise HTTPException(status_code=404, detail="incident not found")
    return proj.model_dump(mode="json")


@router.post("/incidents/{incident_id}/investigate")
def investigate_incident(
    incident_id: str,
    body: InvestigateRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for investigate incident.

    Args:
        incident_id: The incident id value supplied by the caller.
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    with span("sre.incident.investigate", incident_id=incident_id):
        proj = rebuild_incident(incident_id)
        if proj.event_count == 0:
            raise HTTPException(status_code=404, detail="incident not found")
        result = run_investigation(
            incident_id,
            body.observations,
            endpoint_id=body.endpoint_id,
            context=body.context,
            requested_action=body.requested_action,
            explicit_confirmation=body.explicit_confirmation,
        )
        prom_inc("platform_sre_investigation_total")
        return result


@router.get("/incidents/{incident_id}/timeline")
def incident_timeline(
    incident_id: str,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for incident timeline.

    Args:
        incident_id: The incident id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    entries = reconstruct_timeline(incident_id)
    return {"incident_id": incident_id, "entries": [e.model_dump(mode="json") for e in entries]}


@router.get("/incidents/{incident_id}/rca")
def incident_rca(
    incident_id: str,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the GET request for incident rca.

    Args:
        incident_id: The incident id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    proj = rebuild_incident(incident_id)
    if proj.event_count == 0:
        raise HTTPException(status_code=404, detail="incident not found")
    report = build_rca_report(incident_id, projection=proj)
    return report.model_dump(mode="json")


@router.post("/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    body: ResolveIncidentRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for resolve incident.

    Args:
        incident_id: The incident id value supplied by the caller.
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    agg = IncidentAggregate(incident_id)
    if agg.projection.event_count == 0:
        raise HTTPException(status_code=404, detail="incident not found")
    agg.resolve(resolution=body.resolution, actor=body.actor)
    prom_inc("platform_sre_incident_resolved_total")
    return rebuild_incident(incident_id).model_dump(mode="json")


@router.post("/incidents/{incident_id}/mitigate")
def mitigate_incident(
    incident_id: str,
    body: MitigationRequest,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for mitigate incident.

    Args:
        incident_id: The incident id value supplied by the caller.
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    agg = IncidentAggregate(incident_id)
    if agg.projection.event_count == 0:
        raise HTTPException(status_code=404, detail="incident not found")
    agg.attempt_mitigation(action=body.action, outcome=body.outcome, actor=body.actor)
    return rebuild_incident(incident_id).model_dump(mode="json")


@router.post("/incidents/{incident_id}/postmortem")
def create_postmortem(
    incident_id: str,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> dict[str, Any]:
    """Handle the POST request for create postmortem.

    Args:
        incident_id: The incident id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    proj = rebuild_incident(incident_id)
    if proj.event_count == 0:
        raise HTTPException(status_code=404, detail="incident not found")
    doc = generate_postmortem(incident_id, actor=principal.operator_id)
    prom_inc("platform_sre_postmortem_total")
    return {
        "postmortem_id": doc.postmortem_id,
        "incident_id": incident_id,
        "markdown": doc.to_markdown(),
    }
