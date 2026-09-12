"""Evidence Service — tenant-scoped observation and evidence ingest."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlmodel import Session, select

from backend.db.models import EvidenceEvent, ObservationRecord
from backend.db.repositories import content_hash, ensure_endpoint, upsert_evidence
from backend.services.base import TenantContext, ensure_tenant
from windows_network_toolkit.evidence_schema import STANDARD_LIMITATIONS, make_event_id


class EvidenceService:
    """Represent evidence service data used by the toolkit.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    def __init__(self, session: Session, ctx: TenantContext) -> None:
        """Initialize the object with caller supplied state.
        
        Args:
            session: Database session used to read or persist records.
            ctx: The ctx value supplied by the caller.
        
        Returns:
            None.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        self._session = session
        self._ctx = ctx
        ensure_tenant(session, ctx.tenant_id)

    def record_observation(
        self,
        *,
        endpoint_id: str,
        signal_type: str,
        raw_observation: dict[str, Any],
        correlation_id: str = "",
        limitations: list[str] | None = None,
    ) -> ObservationRecord:
        """Record observation.
        
        Args:
            endpoint_id: The endpoint id value supplied by the caller.
            signal_type: The signal type value supplied by the caller.
            raw_observation: The raw observation value supplied by the caller.
            correlation_id: The correlation id value supplied by the caller.
            limitations: The limitations value supplied by the caller.
        
        Returns:
            The ObservationRecord result produced by the operation.
        
        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        obs_id = f"obs-{uuid.uuid4().hex[:12]}"
        row = ObservationRecord(
            observation_id=obs_id,
            tenant_id=self._ctx.tenant_id,
            endpoint_id=endpoint_id,
            signal_type=signal_type,
            raw_observation=raw_observation,
            correlation_id=correlation_id or obs_id,
            limitations=limitations
            or ["Observation is not proof — symptom or snapshot only."],
        )
        self._session.add(row)
        self._session.flush()
        return row

    def ingest_evidence(
        self,
        *,
        endpoint_id: str,
        evidence_type: str,
        raw_snapshot: dict[str, Any],
        source_event_id: str | None = None,
        evidence_tier: str = "T1_STATE_EVIDENCE",
        normalized_fields: dict[str, Any] | None = None,
        limitations: list[str] | None = None,
        observation_id: str | None = None,
    ) -> tuple[EvidenceEvent, bool]:
        """Ingest evidence.
        
        Args:
            endpoint_id: The endpoint id value supplied by the caller.
            evidence_type: The evidence type value supplied by the caller.
            raw_snapshot: The raw snapshot value supplied by the caller.
            source_event_id: The source event id value supplied by the caller.
            evidence_tier: The evidence tier value supplied by the caller.
            normalized_fields: The normalized fields value supplied by the caller.
            limitations: The limitations value supplied by the caller.
            observation_id: The observation id value supplied by the caller.
        
        Returns:
            The tuple[EvidenceEvent, bool] result produced by the operation.
        
        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        ensure_endpoint(self._session, endpoint_id, hostname=endpoint_id)
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        stable = {"endpoint_id": endpoint_id, "source_event_id": source_event_id or ""}
        event_id = make_event_id(ts, evidence_type, stable)
        if not event_id:
            event_id = f"ev-{uuid.uuid4().hex[:12]}"
        c_hash = content_hash(endpoint_id, source_event_id, raw_snapshot)
        lims = limitations or list(STANDARD_LIMITATIONS)
        row, created = upsert_evidence(
            self._session,
            event_id=event_id,
            endpoint_id=endpoint_id,
            source_event_id=source_event_id,
            evidence_type=evidence_type,
            raw_snapshot=raw_snapshot,
            normalized_fields=normalized_fields or {},
            evidence_tier=evidence_tier,
            limitations=lims,
            c_hash=c_hash,
        )
        row.tenant_id = self._ctx.tenant_id
        self._session.add(row)
        if observation_id:
            obs = self._session.exec(
                select(ObservationRecord).where(
                    ObservationRecord.observation_id == observation_id,
                    ObservationRecord.tenant_id == self._ctx.tenant_id,
                )
            ).first()
            if obs:
                obs.raw_observation = {**obs.raw_observation, "linked_evidence_id": row.event_id}
                self._session.add(obs)
        self._session.flush()
        return row, created

    def get_evidence(self, event_id: str) -> EvidenceEvent | None:
        """Get evidence.
        
        Args:
            event_id: The event id value supplied by the caller.
        
        Returns:
            The EvidenceEvent | None result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        row = self._session.exec(
            select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)
        ).first()
        if row and row.tenant_id and row.tenant_id != self._ctx.tenant_id:
            return None
        return row

    def list_evidence(self, *, limit: int = 50) -> list[EvidenceEvent]:
        """List evidence.
        
        Args:
            limit: The limit value supplied by the caller.
        
        Returns:
            The list[EvidenceEvent] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        q = select(EvidenceEvent).order_by(EvidenceEvent.created_at.desc()).limit(limit)
        rows = list(self._session.exec(q).all())
        return [r for r in rows if not r.tenant_id or r.tenant_id == self._ctx.tenant_id]
