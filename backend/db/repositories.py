"""Idempotent persistence helpers for technology-risk tables."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlmodel import Session, select

from backend.db.models import (
    AuditChainEntry,
    ClassificationStatus,
    ControlTestResult,
    Endpoint,
    EvidenceEvent,
    HumanReviewItem,
    IncidentRecord,
    PolicyDecision,
)
from src.platform_core.governance.human_review import REVIEW_CLASSES


def content_hash(endpoint_id: str, source_event_id: str | None, raw: dict[str, Any]) -> str:
    """Content hash.
    
    Args:
        endpoint_id: The endpoint id value supplied by the caller.
        source_event_id: The source event id value supplied by the caller.
        raw: The raw value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    payload = json.dumps(
        {"endpoint_id": endpoint_id, "source_event_id": source_event_id, "raw": raw},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ensure_endpoint(session: Session, endpoint_id: str, hostname: str | None = None) -> Endpoint:
    """Ensure endpoint.
    
    Args:
        session: Database session used to read or persist records.
        endpoint_id: The endpoint id value supplied by the caller.
        hostname: The hostname value supplied by the caller.
    
    Returns:
        The Endpoint result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    row = session.exec(select(Endpoint).where(Endpoint.endpoint_id == endpoint_id)).first()
    if row:
        return row
    ep = Endpoint(endpoint_id=endpoint_id, hostname=hostname or endpoint_id)
    session.add(ep)
    session.flush()
    return ep


def upsert_evidence(
    session: Session,
    *,
    event_id: str,
    endpoint_id: str,
    source_event_id: str | None,
    evidence_type: str,
    raw_snapshot: dict[str, Any],
    normalized_fields: dict[str, Any],
    evidence_tier: str,
    limitations: list[str],
    c_hash: str,
) -> tuple[EvidenceEvent, bool]:
    """Return (row, created). Duplicate content_hash returns existing row."""
    existing = session.exec(select(EvidenceEvent).where(EvidenceEvent.content_hash == c_hash)).first()
    if existing:
        return existing, False
    by_source = None
    if source_event_id:
        by_source = session.exec(
            select(EvidenceEvent).where(
                EvidenceEvent.endpoint_id == endpoint_id,
                EvidenceEvent.source_event_id == source_event_id,
            )
        ).first()
    if by_source:
        return by_source, False

    row = EvidenceEvent(
        event_id=event_id,
        source_event_id=source_event_id,
        content_hash=c_hash,
        endpoint_id=endpoint_id,
        evidence_type=evidence_type,
        evidence_tier=evidence_tier,
        raw_snapshot=raw_snapshot,
        normalized_fields=normalized_fields,
        limitations=limitations,
        classification_status=ClassificationStatus.PENDING.value,
    )
    session.add(row)
    session.flush()
    return row, True


def mark_evidence_status(session: Session, event_id: str, status: str, job_id: str | None = None) -> None:
    """Mark evidence status.
    
    Args:
        session: Database session used to read or persist records.
        event_id: The event id value supplied by the caller.
        status: The status value supplied by the caller.
        job_id: The job id value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    row = session.exec(select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)).first()
    if not row:
        return
    row.classification_status = status
    row.updated_at = datetime.now(UTC)
    if job_id:
        row.job_id = job_id
    session.add(row)


def quarantine_evidence(session: Session, event_id: str, reason: str) -> None:
    """Quarantine evidence.
    
    Args:
        session: Database session used to read or persist records.
        event_id: The event id value supplied by the caller.
        reason: The reason value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    mark_evidence_status(session, event_id, ClassificationStatus.QUARANTINED.value)
    row = session.exec(select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)).first()
    if row:
        lim = list(row.limitations or [])
        lim.append(reason)
        row.limitations = lim
        session.add(row)


def incident_exists_for_evidence(session: Session, event_id: str) -> bool:
    """Incident exists for evidence.
    
    Args:
        session: Database session used to read or persist records.
        event_id: The event id value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return (
        session.exec(select(IncidentRecord).where(IncidentRecord.evidence_event_id == event_id)).first()
        is not None
    )


def store_incident_bundle(
    session: Session,
    *,
    event_id: str,
    endpoint_id: str,
    incident_payload: dict[str, Any],
    control_tests: list[dict[str, Any]],
    policy: dict[str, Any],
) -> IncidentRecord:
    """Store incident bundle.
    
    Args:
        session: Database session used to read or persist records.
        event_id: The event id value supplied by the caller.
        endpoint_id: The endpoint id value supplied by the caller.
        incident_payload: The incident payload value supplied by the caller.
        control_tests: The control tests value supplied by the caller.
        policy: The policy value supplied by the caller.
    
    Returns:
        The IncidentRecord result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    if incident_exists_for_evidence(session, event_id):
        existing = session.exec(
            select(IncidentRecord).where(IncidentRecord.evidence_event_id == event_id)
        ).first()
        assert existing is not None
        return existing

    inc_id = incident_payload.get("incident_id") or f"INC-{uuid.uuid4().hex[:12].upper()}"
    cls = incident_payload.get("incident_class") or incident_payload.get("primary_classification") or "ERROR_INSUFFICIENT_DATA"
    if isinstance(cls, dict):
        cls = cls.get("primary_classification", "ERROR_INSUFFICIENT_DATA")

    existing_by_id = session.exec(
        select(IncidentRecord).where(IncidentRecord.incident_id == inc_id)
    ).first()
    if existing_by_id is not None:
        return existing_by_id

    incident = IncidentRecord(
        incident_id=inc_id,
        evidence_event_id=event_id,
        endpoint_id=endpoint_id,
        primary_classification=str(cls).upper(),
        secondary_signals=list(incident_payload.get("secondary_signals") or []),
        proof_tier=str(incident_payload.get("proof_tier") or incident_payload.get("evidence_tier") or "T1_STATE_EVIDENCE"),
        confidence=float(incident_payload.get("confidence") or 0.5),
        limitations=list(incident_payload.get("limitations") or []),
    )
    session.add(incident)
    session.flush()

    for ct in control_tests:
        session.add(
            ControlTestResult(
                incident_id=inc_id,
                control_id=str(ct.get("control_id", "CTRL-000")),
                test_result=str(ct.get("test_result", "NOT_TESTED")),
                evidence=list(ct.get("evidence") or []),
                limitations=list(ct.get("limitations") or []),
            )
        )

    pd = policy or {}
    session.add(
        PolicyDecision(
            incident_id=inc_id,
            action=str(pd.get("action", "OBSERVE")),
            outcome=str(pd.get("outcome", "PREVIEW_ONLY")),
            dry_run=bool(pd.get("dry_run", True)),
        )
    )

    if incident.primary_classification in REVIEW_CLASSES:
        session.add(
            HumanReviewItem(
                review_id=f"HR-{uuid.uuid4().hex[:12]}",
                incident_id=inc_id,
                evidence_id=event_id,
                classification=incident.primary_classification,
                status="PENDING_REVIEW",
                reason="Accusatory-adjacent classification requires human review.",
            )
        )

    session.flush()
    return incident


def append_audit_chain_row(session: Session, payload: dict[str, Any]) -> AuditChainEntry:
    """Append audit chain row.
    
    Args:
        session: Database session used to read or persist records.
        payload: Request or domain payload supplied by the caller.
    
    Returns:
        The AuditChainEntry result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    last = session.exec(select(AuditChainEntry).order_by(AuditChainEntry.row_index.desc())).first()
    idx = (last.row_index + 1) if last else 0
    prev = last.row_hash if last else "genesis"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    row_hash = hashlib.sha256(f"{prev}:{canonical}".encode()).hexdigest()
    entry = AuditChainEntry(row_index=idx, prev_hash=prev, row_hash=row_hash, payload=payload)
    session.add(entry)
    session.flush()
    return entry


def list_incidents(session: Session, *, limit: int = 50, offset: int = 0) -> list[IncidentRecord]:
    """List incidents.
    
    Args:
        session: Database session used to read or persist records.
        limit: The limit value supplied by the caller.
        offset: The offset value supplied by the caller.
    
    Returns:
        The list[IncidentRecord] result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return list(
        session.exec(select(IncidentRecord).order_by(IncidentRecord.created_at.desc()).offset(offset).limit(limit))
    )


def get_incident(session: Session, incident_id: str) -> IncidentRecord | None:
    """Get incident.
    
    Args:
        session: Database session used to read or persist records.
        incident_id: The incident id value supplied by the caller.
    
    Returns:
        The IncidentRecord | None result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return session.exec(select(IncidentRecord).where(IncidentRecord.incident_id == incident_id)).first()


def get_evidence(session: Session, event_id: str) -> EvidenceEvent | None:
    """Get evidence.
    
    Args:
        session: Database session used to read or persist records.
        event_id: The event id value supplied by the caller.
    
    Returns:
        The EvidenceEvent | None result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return session.exec(select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)).first()


def human_review_queue_depth(session: Session) -> int:
    """Human review queue depth.
    
    Args:
        session: Database session used to read or persist records.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    rows = session.exec(select(HumanReviewItem).where(HumanReviewItem.status == "PENDING_REVIEW")).all()
    return len(list(rows))
