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
    """Compute a stable SHA-256 identity for one evidence snapshot.

    Args:
        endpoint_id: Endpoint that produced the evidence.
        source_event_id: Optional upstream source identifier.
        raw: Raw evidence payload included in the hash material.

    Returns:
        Hex-encoded SHA-256 digest of the canonical JSON identity payload.

    Side effects:
        None.
    """
    payload = json.dumps(
        {"endpoint_id": endpoint_id, "source_event_id": source_event_id, "raw": raw},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ensure_endpoint(session: Session, endpoint_id: str, hostname: str | None = None) -> Endpoint:
    """Return an existing endpoint row or create a minimal placeholder.

    Args:
        session: Active SQLModel session.
        endpoint_id: Stable endpoint identifier.
        hostname: Optional display hostname; defaults to ``endpoint_id``.

    Returns:
        The existing or newly flushed ``Endpoint`` row.

    Side effects:
        May insert and flush one endpoint row.
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
    tenant_id: str | None = None,
) -> tuple[EvidenceEvent, bool]:
    """Insert evidence or return an existing tenant-scoped duplicate.

    Args:
        session: Active SQLModel session.
        event_id: Candidate event identifier for new rows.
        endpoint_id: Endpoint that produced the evidence.
        source_event_id: Optional upstream source identifier.
        evidence_type: Stable evidence category.
        raw_snapshot: Source payload retained for audit review.
        normalized_fields: Derived classifier fields.
        evidence_tier: Ordinal proof/evidence tier.
        limitations: Reviewer-facing constraints.
        c_hash: Content hash used for deduplication.
        tenant_id: Optional tenant scope for identity checks.

    Returns:
        A tuple of ``(row, created)``. Duplicate ``content_hash`` or
        endpoint/source identity returns the existing row with ``created=False``.

    Side effects:
        May insert and flush one evidence row. Existing rows are not rewritten.
    """
    existing_q = select(EvidenceEvent).where(EvidenceEvent.content_hash == c_hash)
    if tenant_id is not None:
        existing_q = existing_q.where(EvidenceEvent.tenant_id == tenant_id)
    existing = session.exec(existing_q).first()
    if existing:
        return existing, False
    by_source = None
    if source_event_id:
        source_q = select(EvidenceEvent).where(
            EvidenceEvent.endpoint_id == endpoint_id,
            EvidenceEvent.source_event_id == source_event_id,
        )
        if tenant_id is not None:
            source_q = source_q.where(EvidenceEvent.tenant_id == tenant_id)
        by_source = session.exec(source_q).first()
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
        tenant_id=tenant_id,
    )
    session.add(row)
    session.flush()
    return row, True


def mark_evidence_status(
    session: Session,
    event_id: str,
    status: str,
    job_id: str | None = None,
) -> None:
    """Update classification status for one evidence event.

    Args:
        session: Active SQLModel session.
        event_id: Evidence event identifier.
        status: New classification status value.
        job_id: Optional worker job identifier to attach.

    Returns:
        None. Missing events are ignored.

    Side effects:
        Updates and flushes the matching evidence row when present.
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
    """Mark evidence as quarantined and append a reviewer-facing reason.

    Args:
        session: Active SQLModel session.
        event_id: Evidence event identifier.
        reason: Quarantine explanation preserved in ``limitations``.

    Returns:
        None.

    Side effects:
        Updates status and limitations on the matching evidence row.
    """
    mark_evidence_status(session, event_id, ClassificationStatus.QUARANTINED.value)
    row = session.exec(select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)).first()
    if row:
        lim = list(row.limitations or [])
        lim.append(reason)
        row.limitations = lim
        session.add(row)


def incident_exists_for_evidence(session: Session, event_id: str) -> bool:
    """Return whether an incident already references the evidence event.

    Args:
        session: Active SQLModel session.
        event_id: Evidence event identifier.

    Returns:
        ``True`` when at least one incident row links to ``event_id``.

    Side effects:
        None.
    """
    return (
        session.exec(
            select(IncidentRecord).where(IncidentRecord.evidence_event_id == event_id)
        ).first()
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
    """Persist an incident with related control tests and policy decision.

    Args:
        session: Active SQLModel session.
        event_id: Source evidence event identifier.
        endpoint_id: Endpoint associated with the incident.
        incident_payload: Classification payload used to populate the incident.
        control_tests: Control-test result dictionaries to attach.
        policy: Policy decision dictionary to attach.

    Returns:
        The existing or newly created ``IncidentRecord``.

    Side effects:
        May insert incident, control-test, policy, and human-review rows, then
        flush the session. Duplicate evidence links return the prior incident.
    """
    if incident_exists_for_evidence(session, event_id):
        existing = session.exec(
            select(IncidentRecord).where(IncidentRecord.evidence_event_id == event_id)
        ).first()
        assert existing is not None
        return existing

    inc_id = incident_payload.get("incident_id") or f"INC-{uuid.uuid4().hex[:12].upper()}"
    cls = (
        incident_payload.get("incident_class")
        or incident_payload.get("primary_classification")
        or "ERROR_INSUFFICIENT_DATA"
    )
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
        proof_tier=str(
            incident_payload.get("proof_tier")
            or incident_payload.get("evidence_tier")
            or "T1_STATE_EVIDENCE"
        ),
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
    """Append one hash-chained backend audit-chain row.

    Args:
        session: Active SQLModel session.
        payload: JSON-compatible event body included in the hash.

    Returns:
        The flushed ``AuditChainEntry``.

    Side effects:
        Inserts and flushes one chain row linked to the previous hash.
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
    """List newest incidents with optional pagination.

    Args:
        session: Active SQLModel session.
        limit: Maximum number of rows to return.
        offset: Number of newest rows to skip.

    Returns:
        Incident rows ordered by ``created_at`` descending.

    Side effects:
        None.
    """
    return list(
        session.exec(
            select(IncidentRecord)
            .order_by(IncidentRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
    )


def get_incident(session: Session, incident_id: str) -> IncidentRecord | None:
    """Fetch one incident by stable identifier.

    Args:
        session: Active SQLModel session.
        incident_id: Incident identifier.

    Returns:
        The matching incident, or ``None`` when absent.

    Side effects:
        None.
    """
    return session.exec(
        select(IncidentRecord).where(IncidentRecord.incident_id == incident_id)
    ).first()


def get_evidence(session: Session, event_id: str) -> EvidenceEvent | None:
    """Fetch one evidence event by identifier without tenant filtering.

    Args:
        session: Active SQLModel session.
        event_id: Evidence event identifier.

    Returns:
        The matching evidence row, or ``None`` when absent.

    Side effects:
        None.
    """
    return session.exec(select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)).first()


def human_review_queue_depth(session: Session) -> int:
    """Count human-review items still pending review.

    Args:
        session: Active SQLModel session.

    Returns:
        Number of rows with status ``PENDING_REVIEW``.

    Side effects:
        None.
    """
    rows = session.exec(
        select(HumanReviewItem).where(HumanReviewItem.status == "PENDING_REVIEW")
    ).all()
    return len(list(rows))
