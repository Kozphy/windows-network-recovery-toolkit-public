"""Versioned technology-risk ingestion and read API."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlmodel import Session, select

from backend.auth.dependencies import get_v1_principal
from backend.auth.rbac import (
    V1Principal,
    assert_can_ingest,
    assert_can_read_audit_reports,
    assert_can_read_incidents,
    assert_can_review,
)
from backend.db import get_engine, init_trisk_schema
from backend.db.models import ClassificationStatus, ControlTestResult, PolicyDecision
from backend.db.repositories import (
    content_hash,
    ensure_endpoint,
    get_evidence,
    get_incident,
    human_review_queue_depth,
    list_incidents,
    upsert_evidence,
)
from backend.queue import get_queue_backend
from backend.trisk_metrics import inc, set_gauge
from src.platform_core.governance.audit_report import build_audit_governance_report
from src.platform_core.governance.chain_of_custody import verify_chain
from windows_network_toolkit.analytics_pipeline import (
    load_audit_rows,
    run_endpoint_analytics_pipeline,
)
from windows_network_toolkit.control_tests import INCIDENT_CONTROL_MAP
from windows_network_toolkit.evidence_schema import STANDARD_LIMITATIONS, make_event_id
from windows_network_toolkit.reporting import build_executive_report

router = APIRouter(prefix="/v1", tags=["technology-risk-v1"])

_REPO = Path(__file__).resolve().parent.parent
_DEFAULT_PIPELINE_FIXTURE = _REPO / "tests" / "fixtures" / "analytics_pipeline_fixture.json"


class EvidenceIngestRequest(BaseModel):
    """Represent evidence ingest request data used by the toolkit.

    Attributes:
        endpoint_id: Field or variant describing endpoint id evidence or state.
        source_event_id: Field or variant describing source event id evidence or state.
        evidence_type: Field or variant describing evidence type evidence or state.
        timestamp_utc: Field or variant describing timestamp utc evidence or state.
        raw_snapshot: Field or variant describing raw snapshot evidence or state.
        normalized_fields: Field or variant describing normalized fields evidence or state.
        evidence_tier: Field or variant describing evidence tier evidence or state.
        limitations: Field or variant describing limitations evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    endpoint_id: str = Field(min_length=1, max_length=128)
    source_event_id: str | None = Field(default=None, max_length=128)
    evidence_type: str = Field(min_length=1, max_length=64)
    timestamp_utc: str = Field(min_length=10)
    raw_snapshot: dict[str, Any] = Field(default_factory=dict)
    normalized_fields: dict[str, Any] = Field(default_factory=dict)
    evidence_tier: str = Field(default="T1_STATE_EVIDENCE")
    limitations: list[str] = Field(default_factory=list)

    @field_validator("raw_snapshot")
    @classmethod
    def _non_empty_snapshot(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not v:
            raise ValueError("raw_snapshot must not be empty")
        return v


class ReviewRequest(BaseModel):
    """Represent review request data used by the toolkit.

    Attributes:
        action: Field or variant describing action evidence or state.
        reason: Field or variant describing reason evidence or state.
        evidence_id: Field or variant describing evidence id evidence or state.
        policy_decision_id: Field or variant describing policy decision id evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    action: str
    reason: str = Field(min_length=1)
    evidence_id: str = ""
    policy_decision_id: str = ""


def _session() -> Session:
    init_trisk_schema()
    return Session(get_engine())


@router.post("/evidence", status_code=202)
def ingest_evidence(
    body: EvidenceIngestRequest,
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the POST request for ingest evidence.

    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    from backend.tracing import span

    assert_can_ingest(principal)
    with span("v1.ingest_evidence", endpoint_id=body.endpoint_id):
        c_hash = content_hash(body.endpoint_id, body.source_event_id, body.raw_snapshot)
        stable = {"endpoint_id": body.endpoint_id, "type": body.evidence_type}
        event_id = make_event_id(body.timestamp_utc, body.evidence_type, stable)
        limitations = list(body.limitations or []) + list(STANDARD_LIMITATIONS[:2])

        with _session() as session:
            ensure_endpoint(session, body.endpoint_id)
            row, created = upsert_evidence(
                session,
                event_id=event_id,
                endpoint_id=body.endpoint_id,
                source_event_id=body.source_event_id,
                evidence_type=body.evidence_type,
                raw_snapshot=body.raw_snapshot,
                normalized_fields=body.normalized_fields,
                evidence_tier=body.evidence_tier,
                limitations=limitations,
                c_hash=c_hash,
            )
            session.commit()
            event_id = row.event_id

        if created:
            inc("evidence_events_ingested_total")
        job = get_queue_backend().enqueue_classification_job(
            event_id=event_id, idempotency_key=c_hash
        )

        from src.platform_core.events import TriskEventType, emit_trisk_event

        emit_trisk_event(
            TriskEventType.EVIDENCE_COLLECTED,
            aggregate_id=f"evidence:{event_id}",
            aggregate_type="evidence",
            actor=principal.actor_id,
            correlation_id=event_id,
            payload={
                "event_id": event_id,
                "endpoint_id": body.endpoint_id,
                "evidence_type": body.evidence_type,
                "content_hash": c_hash,
            },
            limitations=limitations[:3],
        )

        status = ClassificationStatus.PENDING.value
        with _session() as session:
            row = get_evidence(session, event_id)
            if row:
                row.job_id = job.job_id
                status = row.classification_status
                session.add(row)
                session.commit()
                limitations = list(row.limitations or limitations)

        return {
            "event_id": event_id,
            "job_id": job.job_id,
            "classification_status": status,
            "created": created,
            "limitations": limitations,
        }


@router.get("/evidence/{event_id}")
def get_evidence_by_id(
    event_id: str,
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the GET request for get evidence by id.

    Args:
        event_id: The event id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_incidents(principal)
    with _session() as session:
        row = get_evidence(session, event_id)
        if not row:
            raise HTTPException(status_code=404, detail="evidence not found")
        return row.model_dump()


@router.get("/incidents")
def list_incidents_v1(
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Handle the GET request for list incidents v1.

    Args:
        principal: The principal value supplied by the caller.
        limit: The limit value supplied by the caller.
        offset: The offset value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_incidents(principal)
    with _session() as session:
        rows = list_incidents(session, limit=limit, offset=offset)
        return {
            "total": len(rows),
            "limit": limit,
            "offset": offset,
            "items": [r.model_dump() for r in rows],
            "limitations": ["Management information — not a formal audit opinion."],
        }


@router.get("/incidents/{incident_id}")
def get_incident_v1(
    incident_id: str,
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the GET request for get incident v1.

    Args:
        incident_id: The incident id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_incidents(principal)
    with _session() as session:
        inc_row = get_incident(session, incident_id)
        if not inc_row:
            raise HTTPException(status_code=404, detail="incident not found")
        controls = session.exec(
            select(ControlTestResult).where(ControlTestResult.incident_id == incident_id)
        ).all()
        policy = session.exec(
            select(PolicyDecision).where(PolicyDecision.incident_id == incident_id)
        ).first()
        return {
            "incident": inc_row.model_dump(),
            "control_tests": [c.model_dump() for c in controls],
            "policy_decision": policy.model_dump() if policy else None,
        }


@router.post("/incidents/{incident_id}/review")
def post_review(
    incident_id: str,
    body: ReviewRequest,
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the POST request for post review.

    Args:
        incident_id: The incident id value supplied by the caller.
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_review(principal)
    with _session() as session:
        inc_row = get_incident(session, incident_id)
        if not inc_row:
            raise HTTPException(status_code=404, detail="incident not found")
        import uuid

        from backend.db.models import HumanReviewItem

        review = HumanReviewItem(
            review_id=f"HR-{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            evidence_id=body.evidence_id or inc_row.evidence_event_id,
            classification=inc_row.primary_classification,
            policy_decision_id=body.policy_decision_id,
            status=body.action.upper(),
            actor=principal.actor_id,
            reason=body.reason,
        )
        session.add(review)
        session.commit()

        from src.platform_core.events import TriskEventType, emit_trisk_event

        emit_trisk_event(
            TriskEventType.HUMAN_APPROVAL_GRANTED,
            aggregate_id=f"incident:{incident_id}",
            aggregate_type="incident",
            actor=principal.actor_id,
            correlation_id=inc_row.evidence_event_id,
            payload={
                "review_id": review.review_id,
                "action": body.action,
                "incident_id": incident_id,
            },
            limitations=["Human approval — not AI-authorized execution."],
        )
        return {"review_id": review.review_id, "status": review.status}


@router.get("/controls")
def list_controls_v1(
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the GET request for list controls v1.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_incidents(principal)
    return {"incident_control_map": INCIDENT_CONTROL_MAP}


@router.get("/risks")
def list_risks_v1(
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the GET request for list risks v1.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_incidents(principal)
    with _session() as session:
        rows = list_incidents(session, limit=200)
        items = [
            {
                "incident_id": r.incident_id,
                "incident_class": r.primary_classification,
                "risk_level": "MEDIUM" if r.confidence > 0.5 else "LOW",
                "risk_score": min(100.0, r.confidence * 100),
                "limitations": r.limitations,
            }
            for r in rows
        ]
        return {"items": items, "limitations": ["Ordinal scores — not calibrated probability."]}


@router.get("/audit/verify")
def audit_verify_v1(
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
    path: str | None = Query(default=None),
) -> dict[str, Any]:
    """Handle the GET request for audit verify v1.

    Args:
        principal: The principal value supplied by the caller.
        path: Filesystem path used by the operation.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    assert_can_read_audit_reports(principal)
    audit_path = path or os.getenv(
        "TRISK_AUDIT_PATH",
        "tests/fixtures/risk_analytics/audit_sample/incidents.jsonl",
    )
    p = Path(audit_path)
    if not p.is_file():
        from backend.db.models import AuditChainEntry

        with _session() as session:
            rows = session.exec(select(AuditChainEntry).order_by(AuditChainEntry.row_index)).all()
            if not rows:
                return {"verified": True, "source": "db", "rows": 0}
            chain = [{"row_hash": r.row_hash, "prev_hash": r.prev_hash, **r.payload} for r in rows]
            result = verify_chain(chain)
            if not result.get("verified"):
                inc("audit_chain_verification_failures_total")
            return {"verified": result.get("verified", False), "source": "db", **result}

    rows = load_audit_rows(p)
    result = verify_chain(rows)
    if not result.get("verified"):
        inc("audit_chain_verification_failures_total")
    return {"verified": result.get("verified", False), "source": str(p), **result}


@router.get("/reports/executive")
def executive_report_v1(
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the GET request for executive report v1.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_audit_reports(principal)
    audit_dir = Path(os.getenv("PLATFORM_DATA_DIR", "tests/fixtures/risk_analytics/audit_sample"))
    if (audit_dir / "incidents.jsonl").is_file():
        raw = build_audit_governance_report(audit_dir, format="json")
        report = raw if isinstance(raw, dict) else {}
    else:
        fixture = json.loads(_DEFAULT_PIPELINE_FIXTURE.read_text(encoding="utf-8"))
        report = build_executive_report(run_endpoint_analytics_pipeline(fixture=fixture))
    with _session() as session:
        set_gauge("human_review_queue_depth", float(human_review_queue_depth(session)))
    report["limitations"] = list(report.get("limitations") or []) + [
        "Management information — not a formal audit opinion."
    ]

    from src.platform_core.events import TriskEventType, emit_trisk_event

    emit_trisk_event(
        TriskEventType.GOVERNANCE_REPORT_GENERATED,
        aggregate_id="report:executive",
        aggregate_type="report",
        actor=principal.actor_id,
        payload={"kpi_keys": list(report.keys())[:12]},
        limitations=report["limitations"][:2],
    )
    return report


@router.get("/events")
def list_domain_events(
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    aggregate_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Handle the GET request for list domain events.

    Args:
        principal: The principal value supplied by the caller.
        limit: The limit value supplied by the caller.
        offset: The offset value supplied by the caller.
        aggregate_id: The aggregate id value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_audit_reports(principal)
    from src.platform_core.events.projector import list_recent_events

    events = list_recent_events(limit=limit, offset=offset)
    if aggregate_id:
        events = [e for e in events if e.aggregate_id == aggregate_id]
    return {
        "limit": limit,
        "offset": offset,
        "items": [e.model_dump(mode="json") for e in events],
    }


@router.get("/evidence/{event_id}/timeline")
def evidence_timeline(
    event_id: str,
    principal: Annotated[V1Principal, Depends(get_v1_principal)],
) -> dict[str, Any]:
    """Handle the GET request for evidence timeline.

    Args:
        event_id: The event id value supplied by the caller.
        principal: The principal value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_incidents(principal)
    from src.platform_core.events.projector import project_evidence_timeline

    agg = f"evidence:{event_id}"
    return {
        "aggregate_id": agg,
        "timeline": project_evidence_timeline(agg),
    }


@router.get("/health")
def trisk_health_v1() -> dict[str, Any]:
    """Trisk subsystem readiness (liveness for compose)."""
    db_ok = True
    try:
        init_trisk_schema()
        with _session() as session:
            session.exec(select(ControlTestResult).limit(1)).first()
    except Exception:
        db_ok = False
    event_ok = True
    try:
        from src.platform_core.events import get_event_store

        get_event_store()
    except Exception:
        event_ok = False
    return {
        "status": "ok" if db_ok and event_ok else "degraded",
        "database": db_ok,
        "event_store": event_ok,
        "limitations": ["Demo health — not attested SLO."],
    }


# Additive YC/P0 product-control-plane slice. Keeping this mount at the end
# preserves the existing technology-risk route behavior and URL contracts.
from backend.product_v1_routes import router as product_v1_router  # noqa: E402

router.include_router(product_v1_router)
