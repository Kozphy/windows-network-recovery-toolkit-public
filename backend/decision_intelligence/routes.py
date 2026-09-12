"""FastAPI routes for the Decision Intelligence API.

Prefix: ``/decision-intelligence``

Endpoints persist events, evidence, decisions, and outcomes; expose replay and metrics.
All mutating routes require preview-tier RBAC via :func:`backend.platform_auth.get_platform_principal`.

Storage:
    PostgreSQL when ``DATABASE_URL`` is configured; otherwise append-only JSONL under
    ``PLATFORM_DATA_DIR/decision_intelligence/``.

Audit Notes:
    POST handlers append records — they do not execute remediation or trades.
    Failed outcomes (``success=false``) increment ``decision_failures`` Prometheus counter.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.platform_auth import get_platform_principal
from platform_core.rbac import DemoPrincipal, assert_can_preview, assert_can_read_metrics

from .logging_utils import log_structured
from .metrics import (
    inc_decision,
    inc_decision_failure,
    inc_event,
    observe_handler_latency,
    refresh_accuracy_from_learning,
)
from .models import (
    DecisionCreate,
    DecisionFilters,
    DecisionRecord,
    EventCreate,
    EventFilters,
    EventRecord,
    EvidenceCreate,
    EvidenceFilters,
    EvidenceRecord,
    MetricsResponse,
    OutcomeCreate,
    OutcomeFilters,
    OutcomeRecord,
    PaginatedResponse,
    ReplayRequest,
    ReplayResponse,
)
from .service import get_metrics, run_replay
from .store import get_store

router = APIRouter(prefix="/decision-intelligence", tags=["decision-intelligence"])


@router.get("/health")
def di_health() -> dict[str, str]:
    """Handle the GET request for di health.
    
    Args:
        None.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    store = get_store()
    return {"status": "ok", "storage_backend": store.backend_name()}


@router.get("/events", response_model=PaginatedResponse[EventRecord])
def list_events(
    domain: str | None = None,
    category: str | None = None,
    event_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> PaginatedResponse[EventRecord]:
    """Handle the GET request for list events.
    
    Args:
        domain: The domain value supplied by the caller.
        category: The category value supplied by the caller.
        event_id: The event id value supplied by the caller.
        since: The since value supplied by the caller.
        until: The until value supplied by the caller.
        page: The page value supplied by the caller.
        page_size: The page size value supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    with observe_handler_latency():
        filters = EventFilters(
            domain=domain, category=category, event_id=event_id, since=since, until=until
        )
        result = get_store().list_events(filters, page, page_size)
    log_structured("list_events", operator=principal.operator_id, total=result.total, page=page)
    return result


@router.post("/events", response_model=EventRecord, status_code=201)
def create_event(
    body: EventCreate,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> EventRecord:
    """Handle the POST request for create event.
    
    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    with observe_handler_latency():
        record = get_store().create_event(body)
    inc_event()
    log_structured("create_event", operator=principal.operator_id, event_id=record.event_id)
    return record


@router.get("/evidence", response_model=PaginatedResponse[EvidenceRecord])
def list_evidence(
    event_id: str | None = None,
    decision_id: str | None = None,
    kind: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> PaginatedResponse[EvidenceRecord]:
    """Handle the GET request for list evidence.
    
    Args:
        event_id: The event id value supplied by the caller.
        decision_id: The decision id value supplied by the caller.
        kind: The kind value supplied by the caller.
        page: The page value supplied by the caller.
        page_size: The page size value supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    with observe_handler_latency():
        filters = EvidenceFilters(event_id=event_id, decision_id=decision_id, kind=kind)
        result = get_store().list_evidence(filters, page, page_size)
    log_structured("list_evidence", operator=principal.operator_id, total=result.total)
    return result


@router.post("/evidence", response_model=EvidenceRecord, status_code=201)
def create_evidence(
    body: EvidenceCreate,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> EvidenceRecord:
    """Handle the POST request for create evidence.
    
    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    with observe_handler_latency():
        record = get_store().create_evidence(body)
    log_structured("create_evidence", operator=principal.operator_id, evidence_id=record.evidence_id)
    return record


@router.get("/decisions", response_model=PaginatedResponse[DecisionRecord])
def list_decisions(
    domain: str | None = None,
    decision_id: str | None = None,
    policy_status: str | None = None,
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> PaginatedResponse[DecisionRecord]:
    """Handle the GET request for list decisions.
    
    Args:
        domain: The domain value supplied by the caller.
        decision_id: The decision id value supplied by the caller.
        policy_status: The policy status value supplied by the caller.
        min_confidence: The min confidence value supplied by the caller.
        page: The page value supplied by the caller.
        page_size: The page size value supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    assert_can_read_metrics(principal)
    with observe_handler_latency():
        filters = DecisionFilters(
            domain=domain,
            decision_id=decision_id,
            policy_status=policy_status,
            min_confidence=min_confidence,
        )
        result = get_store().list_decisions(filters, page, page_size)
    log_structured("list_decisions", operator=principal.operator_id, total=result.total)
    return result


@router.post("/decisions", response_model=DecisionRecord, status_code=201)
def create_decision(
    body: DecisionCreate,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> DecisionRecord:
    """Handle the POST request for create decision.
    
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
    assert_can_preview(principal)
    with observe_handler_latency():
        record = get_store().create_decision(body)
    inc_decision()
    log_structured("create_decision", operator=principal.operator_id, decision_id=record.decision_id)
    return record


@router.get("/outcomes", response_model=PaginatedResponse[OutcomeRecord])
def list_outcomes(
    decision_id: str | None = None,
    success: bool | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> PaginatedResponse[OutcomeRecord]:
    """Handle the GET request for list outcomes.
    
    Args:
        decision_id: The decision id value supplied by the caller.
        success: The success value supplied by the caller.
        page: The page value supplied by the caller.
        page_size: The page size value supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    with observe_handler_latency():
        filters = OutcomeFilters(decision_id=decision_id, success=success)
        result = get_store().list_outcomes(filters, page, page_size)
    log_structured("list_outcomes", operator=principal.operator_id, total=result.total)
    return result


@router.post("/outcomes", response_model=OutcomeRecord, status_code=201)
def create_outcome(
    body: OutcomeCreate,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> OutcomeRecord:
    """Handle the POST request for create outcome.
    
    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_preview(principal)
    with observe_handler_latency():
        record = get_store().create_outcome(body)
    if not record.success:
        inc_decision_failure()
    log_structured("create_outcome", operator=principal.operator_id, outcome_id=record.outcome_id)
    return record


@router.post("/replay", response_model=ReplayResponse)
def replay(
    body: ReplayRequest | None = None,
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> ReplayResponse:
    """Handle the POST request for replay.
    
    Args:
        body: Request or domain payload supplied by the caller.
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    with observe_handler_latency():
        result = run_replay(body or ReplayRequest())
    refresh_accuracy_from_learning(float(result.metrics.get("decision_accuracy", 0.0)))
    log_structured(
        "replay",
        operator=principal.operator_id,
        outcome_count=result.outcome_count,
        digest=result.content_digest[:16],
    )
    return result


@router.get("/metrics", response_model=MetricsResponse)
def metrics(
    principal: DemoPrincipal = Depends(get_platform_principal),
) -> MetricsResponse:
    """Handle the GET request for metrics.
    
    Args:
        principal: The principal value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    assert_can_read_metrics(principal)
    with observe_handler_latency():
        result = get_metrics()
    refresh_accuracy_from_learning(float(result.learning.get("decision_accuracy", 0.0)))
    log_structured("metrics", operator=principal.operator_id, backend=result.storage_backend)
    return result
