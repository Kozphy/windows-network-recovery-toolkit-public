"""SQLModel tables for technology-risk evidence pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Column, UniqueConstraint
from sqlmodel import Field, SQLModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ClassificationStatus(StrEnum):
    """Represent classification status data used by the toolkit.
    
    Attributes:
        PENDING: Field or variant describing p e n d i n g evidence or state.
        CLASSIFIED: Field or variant describing c l a s s i f i e d evidence or state.
        REVIEW_REQUIRED: Field or variant describing r e v i e w r e q u i r e d evidence or state.
        REJECTED: Field or variant describing r e j e c t e d evidence or state.
        QUARANTINED: Field or variant describing q u a r a n t i n e d evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    PENDING = "pending"
    CLASSIFIED = "classified"
    REVIEW_REQUIRED = "review_required"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


class Endpoint(SQLModel, table=True):
    """Represent endpoint data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        endpoint_id: Field or variant describing endpoint id evidence or state.
        hostname: Field or variant describing hostname evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.
        created_at: Field or variant describing created at evidence or state.
        updated_at: Field or variant describing updated at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_endpoints"

    id: int | None = Field(default=None, primary_key=True)
    endpoint_id: str = Field(index=True, unique=True, max_length=128)
    hostname: str | None = Field(default=None, max_length=256)
    tenant_id: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class EvidenceEvent(SQLModel, table=True):
    """Represent evidence event data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        event_id: Field or variant describing event id evidence or state.
        source_event_id: Field or variant describing source event id evidence or state.
        content_hash: Field or variant describing content hash evidence or state.
        endpoint_id: Field or variant describing endpoint id evidence or state.
        evidence_type: Field or variant describing evidence type evidence or state.
        evidence_tier: Field or variant describing evidence tier evidence or state.
        raw_snapshot: Field or variant describing raw snapshot evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_evidence_events"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "source_event_id", name="uq_endpoint_source_event"),
    )

    id: int | None = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True, max_length=64)
    source_event_id: str | None = Field(default=None, max_length=128)
    content_hash: str = Field(index=True, max_length=64)
    endpoint_id: str = Field(index=True, max_length=128)
    evidence_type: str = Field(max_length=64)
    evidence_tier: str = Field(default="T1_STATE_EVIDENCE", max_length=64)
    raw_snapshot: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    normalized_fields: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    classification_status: str = Field(default=ClassificationStatus.PENDING.value, max_length=32)
    job_id: str | None = Field(default=None, max_length=64)
    tenant_id: str | None = Field(default=None, max_length=64, index=True)
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class IncidentRecord(SQLModel, table=True):
    """Represent incident record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        evidence_event_id: Field or variant describing evidence event id evidence or state.
        endpoint_id: Field or variant describing endpoint id evidence or state.
        primary_classification: Field or variant describing primary classification evidence or state.
        secondary_signals: Field or variant describing secondary signals evidence or state.
        proof_tier: Field or variant describing proof tier evidence or state.
        confidence: Field or variant describing confidence evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_incidents"

    id: int | None = Field(default=None, primary_key=True)
    incident_id: str = Field(index=True, unique=True, max_length=64)
    evidence_event_id: str = Field(foreign_key="trisk_evidence_events.event_id", index=True)
    endpoint_id: str = Field(index=True, max_length=128)
    primary_classification: str = Field(max_length=64)
    secondary_signals: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    proof_tier: str = Field(default="T1_STATE_EVIDENCE", max_length=64)
    confidence: float = Field(default=0.5)
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tenant_id: str | None = Field(default=None, max_length=64, index=True)
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class ControlTestResult(SQLModel, table=True):
    """Represent control test result data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        control_id: Field or variant describing control id evidence or state.
        test_result: Field or variant describing test result evidence or state.
        evidence: Field or variant describing evidence evidence or state.
        limitations: Field or variant describing limitations evidence or state.
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_control_tests"

    id: int | None = Field(default=None, primary_key=True)
    incident_id: str = Field(foreign_key="trisk_incidents.incident_id", index=True)
    control_id: str = Field(max_length=32)
    test_result: str = Field(max_length=32)
    evidence: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utc_now)


class PolicyDecision(SQLModel, table=True):
    """Represent policy decision data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        action: Field or variant describing action evidence or state.
        outcome: Field or variant describing outcome evidence or state.
        dry_run: Field or variant describing dry run evidence or state.
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_policy_decisions"

    id: int | None = Field(default=None, primary_key=True)
    incident_id: str = Field(foreign_key="trisk_incidents.incident_id", index=True)
    action: str = Field(max_length=64)
    outcome: str = Field(max_length=64)
    dry_run: bool = Field(default=True)
    created_at: datetime = Field(default_factory=_utc_now)


class RiskDecisionRecord(SQLModel, table=True):
    """Represent risk decision record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        actor: Field or variant describing actor evidence or state.
        reason: Field or variant describing reason evidence or state.
        policy_decision_id: Field or variant describing policy decision id evidence or state.
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_risk_decisions"

    id: int | None = Field(default=None, primary_key=True)
    decision_id: str = Field(unique=True, max_length=64)
    incident_id: str = Field(foreign_key="trisk_incidents.incident_id", index=True)
    actor: str = Field(max_length=128)
    reason: str = Field(default="")
    policy_decision_id: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=_utc_now)


class HumanReviewItem(SQLModel, table=True):
    """Represent human review item data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        review_id: Field or variant describing review id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        evidence_id: Field or variant describing evidence id evidence or state.
        classification: Field or variant describing classification evidence or state.
        policy_decision_id: Field or variant describing policy decision id evidence or state.
        status: Field or variant describing status evidence or state.
        actor: Field or variant describing actor evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_human_reviews"

    id: int | None = Field(default=None, primary_key=True)
    review_id: str = Field(unique=True, max_length=64)
    incident_id: str = Field(foreign_key="trisk_incidents.incident_id", index=True)
    evidence_id: str = Field(max_length=64)
    classification: str = Field(max_length=64)
    policy_decision_id: str = Field(default="", max_length=64)
    status: str = Field(default="PENDING_REVIEW", max_length=32)
    actor: str | None = Field(default=None, max_length=128)
    reason: str = Field(default="")
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class AuditChainEntry(SQLModel, table=True):
    """Represent audit chain entry data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        row_index: Field or variant describing row index evidence or state.
        prev_hash: Field or variant describing prev hash evidence or state.
        row_hash: Field or variant describing row hash evidence or state.
        payload: Field or variant describing payload evidence or state.
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_audit_chain"

    id: int | None = Field(default=None, primary_key=True)
    row_index: int = Field(index=True)
    prev_hash: str = Field(max_length=128)
    row_hash: str = Field(max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utc_now)


class TriskDomainEventRow(SQLModel, table=True):
    """Represent trisk domain event row data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        event_id: Field or variant describing event id evidence or state.
        event_type: Field or variant describing event type evidence or state.
        aggregate_id: Field or variant describing aggregate id evidence or state.
        aggregate_type: Field or variant describing aggregate type evidence or state.
        sequence: Field or variant describing sequence evidence or state.
        actor: Field or variant describing actor evidence or state.
        correlation_id: Field or variant describing correlation id evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_domain_events"

    id: int | None = Field(default=None, primary_key=True)
    event_id: str = Field(unique=True, max_length=64)
    event_type: str = Field(max_length=64, index=True)
    aggregate_id: str = Field(max_length=128, index=True)
    aggregate_type: str = Field(max_length=32)
    sequence: int = Field(ge=1)
    actor: str = Field(default="system", max_length=128)
    correlation_id: str = Field(default="", max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utc_now)


class TenantRecord(SQLModel, table=True):
    """Represent tenant record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.
        display_name: Field or variant describing display name evidence or state.
        status: Field or variant describing status evidence or state.
        created_at: Field or variant describing created at evidence or state.
        updated_at: Field or variant describing updated at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_tenants"

    id: int | None = Field(default=None, primary_key=True)
    tenant_id: str = Field(unique=True, max_length=64, index=True)
    display_name: str = Field(max_length=256)
    status: str = Field(default="active", max_length=32)
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class ObservationRecord(SQLModel, table=True):
    """Represent observation record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        observation_id: Field or variant describing observation id evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.
        endpoint_id: Field or variant describing endpoint id evidence or state.
        signal_type: Field or variant describing signal type evidence or state.
        raw_observation: Field or variant describing raw observation evidence or state.
        limitations: Field or variant describing limitations evidence or state.
        correlation_id: Field or variant describing correlation id evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_observations"

    id: int | None = Field(default=None, primary_key=True)
    observation_id: str = Field(unique=True, max_length=64, index=True)
    tenant_id: str = Field(max_length=64, index=True)
    endpoint_id: str = Field(max_length=128)
    signal_type: str = Field(max_length=64)
    raw_observation: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    correlation_id: str = Field(default="", max_length=128)
    created_at: datetime = Field(default_factory=_utc_now)


class HypothesisRecord(SQLModel, table=True):
    """Represent hypothesis record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        hypothesis_id: Field or variant describing hypothesis id evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.
        observation_id: Field or variant describing observation id evidence or state.
        evidence_event_id: Field or variant describing evidence event id evidence or state.
        label: Field or variant describing label evidence or state.
        confidence_score: Field or variant describing confidence score evidence or state.
        confidence_ordinal: Field or variant describing confidence ordinal evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_hypotheses"

    id: int | None = Field(default=None, primary_key=True)
    hypothesis_id: str = Field(unique=True, max_length=64, index=True)
    tenant_id: str = Field(max_length=64, index=True)
    observation_id: str | None = Field(default=None, max_length=64)
    evidence_event_id: str | None = Field(default=None, max_length=64)
    label: str = Field(max_length=128)
    confidence_score: float = Field(default=0.5)
    confidence_ordinal: str = Field(default="medium", max_length=16)
    status: str = Field(default="proposed", max_length=32)
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class PlatformDecisionRecord(SQLModel, table=True):
    """Represent platform decision record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        hypothesis_id: Field or variant describing hypothesis id evidence or state.
        evidence_event_id: Field or variant describing evidence event id evidence or state.
        confidence_score: Field or variant describing confidence score evidence or state.
        confidence_label: Field or variant describing confidence label evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_platform_decisions"

    id: int | None = Field(default=None, primary_key=True)
    decision_id: str = Field(unique=True, max_length=64, index=True)
    tenant_id: str = Field(max_length=64, index=True)
    incident_id: str | None = Field(default=None, max_length=64)
    hypothesis_id: str | None = Field(default=None, max_length=64)
    evidence_event_id: str = Field(max_length=64)
    confidence_score: float = Field(default=0.5)
    confidence_label: str = Field(default="medium", max_length=16)
    policy_outcome: str = Field(default="PREVIEW_ONLY", max_length=64)
    recommended_action: str = Field(default="OBSERVE", max_length=64)
    execution_authority: str = Field(default="preview_only", max_length=64)
    human_approval_required: bool = Field(default=True)
    human_approval_status: str = Field(default="pending", max_length=32)
    actor: str = Field(default="system", max_length=128)
    rationale: str = Field(default="")
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class PolicyPackRecord(SQLModel, table=True):
    """Represent policy pack record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        pack_id: Field or variant describing pack id evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.
        version: Field or variant describing version evidence or state.
        yaml_content: Field or variant describing yaml content evidence or state.
        active: Field or variant describing active evidence or state.
        created_at: Field or variant describing created at evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_policy_packs"

    id: int | None = Field(default=None, primary_key=True)
    pack_id: str = Field(unique=True, max_length=64, index=True)
    tenant_id: str = Field(max_length=64, index=True)
    version: str = Field(default="1.0.0", max_length=32)
    yaml_content: str
    active: bool = Field(default=False)
    created_at: datetime = Field(default_factory=_utc_now)


class AuditLogRecord(SQLModel, table=True):
    """Represent audit log record data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        log_id: Field or variant describing log id evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.
        correlation_id: Field or variant describing correlation id evidence or state.
        event_type: Field or variant describing event type evidence or state.
        actor: Field or variant describing actor evidence or state.
        resource_type: Field or variant describing resource type evidence or state.
        resource_id: Field or variant describing resource id evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    __tablename__ = "trisk_audit_logs"

    id: int | None = Field(default=None, primary_key=True)
    log_id: str = Field(unique=True, max_length=64, index=True)
    tenant_id: str = Field(max_length=64, index=True)
    correlation_id: str = Field(default="", max_length=128, index=True)
    event_type: str = Field(max_length=64)
    actor: str = Field(default="system", max_length=128)
    resource_type: str = Field(default="decision", max_length=32)
    resource_id: str = Field(default="", max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    prev_hash: str = Field(default="genesis", max_length=128)
    row_hash: str = Field(max_length=128)
    created_at: datetime = Field(default_factory=_utc_now)
