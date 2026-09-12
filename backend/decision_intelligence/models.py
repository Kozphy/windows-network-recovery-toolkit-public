"""Typed OpenAPI models for the Decision Intelligence API.

Request/response shapes for ``/decision-intelligence/*`` routes. Timestamps are
UTC ISO-8601 strings unless noted on individual fields.

Validation boundaries:
    - Pagination: ``page`` >= 1, ``page_size`` 1–100.
    - Confidence filters: 0.0–1.0 when present.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Represent pagination params data used by the toolkit.
    
    Attributes:
        page: Field or variant describing page evidence or state.
        page_size: Field or variant describing page size evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class PaginatedResponse(BaseModel, Generic[T]):
    """Represent paginated response data used by the toolkit.
    
    Attributes:
        items: Field or variant describing items evidence or state.
        page: Field or variant describing page evidence or state.
        page_size: Field or variant describing page size evidence or state.
        total: Field or variant describing total evidence or state.
        has_more: Field or variant describing has more evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    items: list[T]
    page: int
    page_size: int
    total: int
    has_more: bool


class EventFilters(BaseModel):
    """Represent event filters data used by the toolkit.
    
    Attributes:
        domain: Field or variant describing domain evidence or state.
        category: Field or variant describing category evidence or state.
        event_id: Field or variant describing event id evidence or state.
        since: Field or variant describing since evidence or state.
        until: Field or variant describing until evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    domain: str | None = None
    category: str | None = None
    event_id: str | None = None
    since: str | None = None
    until: str | None = None


class EvidenceFilters(BaseModel):
    """Represent evidence filters data used by the toolkit.
    
    Attributes:
        event_id: Field or variant describing event id evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        kind: Field or variant describing kind evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    event_id: str | None = None
    decision_id: str | None = None
    kind: str | None = None


class DecisionFilters(BaseModel):
    """Represent decision filters data used by the toolkit.
    
    Attributes:
        domain: Field or variant describing domain evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        policy_status: Field or variant describing policy status evidence or state.
        min_confidence: Field or variant describing min confidence evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    domain: str | None = None
    decision_id: str | None = None
    policy_status: str | None = None
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class OutcomeFilters(BaseModel):
    """Represent outcome filters data used by the toolkit.
    
    Attributes:
        decision_id: Field or variant describing decision id evidence or state.
        success: Field or variant describing success evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    decision_id: str | None = None
    success: bool | None = None


class EventCreate(BaseModel):
    """Represent event create data used by the toolkit.
    
    Attributes:
        event_id: Field or variant describing event id evidence or state.
        domain: Field or variant describing domain evidence or state.
        title: Field or variant describing title evidence or state.
        category: Field or variant describing category evidence or state.
        timestamp_utc: Field or variant describing timestamp utc evidence or state.
        payload: Field or variant describing payload evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    event_id: str
    domain: str = "generic"
    title: str
    category: str = ""
    timestamp_utc: str
    payload: dict[str, Any] = Field(default_factory=dict)


class EventRecord(EventCreate):
    """Represent event record data used by the toolkit.
    
    Attributes:
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    created_at: str | None = None


class EvidenceCreate(BaseModel):
    """Represent evidence create data used by the toolkit.
    
    Attributes:
        evidence_id: Field or variant describing evidence id evidence or state.
        event_id: Field or variant describing event id evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        label: Field or variant describing label evidence or state.
        kind: Field or variant describing kind evidence or state.
        weight: Field or variant describing weight evidence or state.
        supports_decision: Field or variant describing supports decision evidence or state.
        detail: Field or variant describing detail evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    evidence_id: str
    event_id: str = ""
    decision_id: str = ""
    label: str
    kind: str = "observation"
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    supports_decision: bool | None = None
    detail: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class EvidenceRecord(EvidenceCreate):
    """Represent evidence record data used by the toolkit.
    
    Attributes:
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    created_at: str | None = None


class DecisionCreate(BaseModel):
    """Represent decision create data used by the toolkit.
    
    Attributes:
        decision_id: Field or variant describing decision id evidence or state.
        domain: Field or variant describing domain evidence or state.
        title: Field or variant describing title evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        risk_score: Field or variant describing risk score evidence or state.
        policy_status: Field or variant describing policy status evidence or state.
        payload: Field or variant describing payload evidence or state.
        content_digest: Field or variant describing content digest evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    decision_id: str
    domain: str
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=100.0)
    policy_status: str = "PREVIEW"
    payload: dict[str, Any] = Field(default_factory=dict)
    content_digest: str = ""
    timestamp_utc: str


class DecisionRecord(DecisionCreate):
    """Represent decision record data used by the toolkit.
    
    Attributes:
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    created_at: str | None = None


class OutcomeCreate(BaseModel):
    """Represent outcome create data used by the toolkit.
    
    Attributes:
        outcome_id: Field or variant describing outcome id evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        outcome: Field or variant describing outcome evidence or state.
        success: Field or variant describing success evidence or state.
        predicted_success: Field or variant describing predicted success evidence or state.
        cost: Field or variant describing cost evidence or state.
        time_to_resolution: Field or variant describing time to resolution evidence or state.
        notes: Field or variant describing notes evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    outcome_id: str
    decision_id: str
    outcome: str
    success: bool
    predicted_success: bool = True
    cost: float = Field(ge=0.0, default=0.0)
    time_to_resolution: float = Field(ge=0.0, default=0.0)
    notes: str = ""
    recorded_at_utc: str


class OutcomeRecord(OutcomeCreate):
    """Represent outcome record data used by the toolkit.
    
    Attributes:
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    created_at: str | None = None


class ReplayRequest(BaseModel):
    """Represent replay request data used by the toolkit.
    
    Attributes:
        fixture_path: Field or variant describing fixture path evidence or state.
        include_engine_digest: Field or variant describing include engine digest evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    fixture_path: str | None = None
    include_engine_digest: bool = True


class ReplayResponse(BaseModel):
    """Represent replay response data used by the toolkit.
    
    Attributes:
        outcome_count: Field or variant describing outcome count evidence or state.
        content_digest: Field or variant describing content digest evidence or state.
        metrics: Field or variant describing metrics evidence or state.
        report_excerpt: Field or variant describing report excerpt evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    outcome_count: int
    content_digest: str
    metrics: dict[str, Any]
    report_excerpt: str = ""


class MetricsResponse(BaseModel):
    """Represent metrics response data used by the toolkit.
    
    Attributes:
        store: Field or variant describing store evidence or state.
        learning: Field or variant describing learning evidence or state.
        storage_backend: Field or variant describing storage backend evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    store: dict[str, int]
    learning: dict[str, Any]
    storage_backend: str
