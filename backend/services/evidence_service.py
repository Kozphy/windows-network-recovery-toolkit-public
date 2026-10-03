"""Record observations and deduplicated evidence for one tenant.

Module responsibility:
    Persist the distinction between raw observations and normalized evidence,
    attach evidence to endpoints, and preserve limitations for later
    classification and audit review.

System placement:
    Called by backend ingestion routes before classification and policy
    evaluation. Repository helpers provide stable event IDs and content hashes.

Key invariants:
    Tenant context scopes all reads and writes. Observations remain explicitly
    non-proof. Evidence ingestion is replay-friendly: stable source metadata,
    content hashing, and tenant identity allow repository upsert behavior to
    suppress duplicates without cross-tenant matches. Legacy rows with a null
    ``tenant_id`` are excluded from tenant-scoped reads.

Side effects:
    Creates or updates database rows and may link an observation to an evidence
    event. Timestamps are stored as UTC strings in the existing schema.

Failure modes:
    Database errors propagate. Missing observation links do not fail evidence
    ingestion; the evidence row remains available for review.

Audit Notes:
    Review ``evidence_tier``, ``limitations``, ``source_event_id``, and
    ``content_hash`` before treating an event as proof. Re-ingest the same
    source snapshot to verify deduplication rather than creating a second
    independent observation.
"""

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
    """Tenant-scoped observation and evidence persistence service."""

    def __init__(self, session: Session, ctx: TenantContext) -> None:
        """Bind the service to one SQLModel session and tenant context.

        Args:
            session: Active database session owned by the caller.
            ctx: Tenant and actor identity used for scoped reads/writes.

        Side effects:
            Ensures the tenant row exists before later operations run.
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
        """Persist a raw observation with an explicit non-proof limitation.

        Args:
            endpoint_id: Endpoint associated with the observation.
            signal_type: Stable signal category.
            raw_observation: JSON-compatible source snapshot.
            correlation_id: Optional workflow correlation identifier.
            limitations: Reviewer-facing evidence limitations.

        Returns:
            The flushed observation record.
        """
        obs_id = f"obs-{uuid.uuid4().hex[:12]}"
        row = ObservationRecord(
            observation_id=obs_id,
            tenant_id=self._ctx.tenant_id,
            endpoint_id=endpoint_id,
            signal_type=signal_type,
            raw_observation=raw_observation,
            correlation_id=correlation_id or obs_id,
            limitations=limitations or ["Observation is not proof — symptom or snapshot only."],
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
        """Upsert normalized evidence and optionally link its observation.

        Args:
            endpoint_id: Endpoint that produced the evidence.
            evidence_type: Stable evidence category.
            raw_snapshot: Source payload retained for audit review.
            source_event_id: Upstream event identifier used for stable identity.
            evidence_tier: Ordinal proof/evidence tier.
            normalized_fields: Derived fields used by classifiers.
            limitations: Constraints preserved with the evidence.
            observation_id: Optional tenant-scoped observation to link.

        Returns:
            A tuple of the evidence row and a boolean indicating whether a new
            row was created.

        Side effects:
            Ensures the endpoint exists, upserts evidence, optionally updates
            one observation link, and flushes the session. The caller controls
            transaction commit.
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
            tenant_id=self._ctx.tenant_id,
        )
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
        """Return one evidence event only when it belongs to the active tenant."""
        return self._session.exec(
            select(EvidenceEvent).where(
                EvidenceEvent.event_id == event_id,
                EvidenceEvent.tenant_id == self._ctx.tenant_id,
            )
        ).first()

    def list_evidence(self, *, limit: int = 50) -> list[EvidenceEvent]:
        """Return the newest evidence rows owned by the active tenant."""
        q = (
            select(EvidenceEvent)
            .where(EvidenceEvent.tenant_id == self._ctx.tenant_id)
            .order_by(EvidenceEvent.created_at.desc())
            .limit(limit)
        )
        return list(self._session.exec(q).all())
