"""Append and verify tenant-scoped hash-chained audit records.

Module responsibility:
    Persist audit events in the backend database and expose tenant-filtered
    listing and chain verification to route handlers.

System placement:
    Used by backend pipeline and governance routes after policy, evidence, or
    workflow decisions. The service is separate from the canonical JSONL audit
    writer in ``src/platform_core/audit``.

Key invariants:
    Every row belongs to the active tenant context. Each row hashes the prior
    tenant row and a canonicalized event body. Same-process concurrent appends
    for one tenant are serialized, and the chain head is selected with a row
    lock when the database dialect supports it. Confirmation secrets are not
    part of this service's contract.

Side effects:
    ``append`` inserts and flushes one database row. Read and verification
    methods do not mutate state.

Failure modes:
    Database or session errors propagate to the caller. Chain verification
    returns a structured failure identifying the first mismatched row.

Audit Notes:
    Preserve the tenant, correlation ID, event payload, and failed row ID when
    investigating. A valid hash chain proves internal consistency, not truth of
    the recorded event.
"""

from __future__ import annotations

import json
import threading
import uuid
from typing import Any

from sqlmodel import Session, select

from backend.db.models import AuditLogRecord
from backend.services.base import TenantContext, ensure_tenant
from src.platform_core.governance.chain_of_custody import chain_hash

_tenant_chain_locks: dict[str, threading.Lock] = {}
_tenant_chain_locks_guard = threading.Lock()


def _chain_lock_for_tenant(tenant_id: str) -> threading.Lock:
    """Return a process-local lock for one tenant audit chain head."""
    with _tenant_chain_locks_guard:
        lock = _tenant_chain_locks.get(tenant_id)
        if lock is None:
            lock = threading.Lock()
            _tenant_chain_locks[tenant_id] = lock
        return lock


class AuditService:
    """Tenant-scoped database audit service.

    The constructor ensures the tenant exists before any append or read. The
    caller owns transaction commit/rollback semantics through the SQLModel
    session.
    """

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

    def _last_hash(self) -> str:
        """Return the newest tenant chain hash, locking the head when supported.

        Returns:
            The latest ``row_hash`` for the active tenant, or ``genesis`` when
            the tenant chain is empty.

        Side effects:
            Issues a ``SELECT ... FOR UPDATE`` against the newest tenant row
            when the database dialect supports row locking.
        """
        row = self._session.exec(
            select(AuditLogRecord)
            .where(AuditLogRecord.tenant_id == self._ctx.tenant_id)
            .order_by(AuditLogRecord.id.desc())
            .with_for_update()
        ).first()
        return row.row_hash if row else "genesis"

    def append(
        self,
        *,
        event_type: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, Any],
        correlation_id: str = "",
    ) -> AuditLogRecord:
        """Append one event to the active tenant's hash chain.

        Args:
            event_type: Stable event classification.
            resource_type: Type of resource affected or observed.
            resource_id: Resource identifier.
            payload: JSON-compatible event details.
            correlation_id: Optional workflow/request correlation identifier.

        Returns:
            The flushed database record, including previous and current hashes.

        Side effects:
            Adds and flushes one row; the surrounding transaction still
            controls commit durability. Same-process concurrent appends for
            one tenant are serialized so ``prev_hash`` remains consistent.
        """
        with _chain_lock_for_tenant(self._ctx.tenant_id):
            prev = self._last_hash()
            body = {
                "tenant_id": self._ctx.tenant_id,
                "event_type": event_type,
                "actor": self._ctx.actor_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "payload": payload,
                "correlation_id": correlation_id,
            }
            row_hash = chain_hash(prev, json.dumps(body, sort_keys=True, separators=(",", ":")))
            log_id = f"alog-{uuid.uuid4().hex[:12]}"
            row = AuditLogRecord(
                log_id=log_id,
                tenant_id=self._ctx.tenant_id,
                correlation_id=correlation_id,
                event_type=event_type,
                actor=self._ctx.actor_id,
                resource_type=resource_type,
                resource_id=resource_id,
                payload=payload,
                prev_hash=prev,
                row_hash=row_hash,
            )
            self._session.add(row)
            self._session.flush()
            return row

    def list_logs(
        self, *, limit: int = 50, correlation_id: str | None = None
    ) -> list[AuditLogRecord]:
        """Return newest tenant-scoped audit rows, optionally by correlation.

        Args:
            limit: Maximum number of rows to return.
            correlation_id: Optional correlation filter.

        Returns:
            Matching audit rows ordered by ``created_at`` descending.

        Side effects:
            None.
        """
        q = select(AuditLogRecord).where(AuditLogRecord.tenant_id == self._ctx.tenant_id)
        if correlation_id:
            q = q.where(AuditLogRecord.correlation_id == correlation_id)
        q = q.order_by(AuditLogRecord.created_at.desc()).limit(limit)
        return list(self._session.exec(q).all())

    def verify_chain(self) -> dict[str, Any]:
        """Verify every tenant row against its predecessor hash.

        Returns:
            A JSON-ready result with ``verified``, row count, tenant ID, and,
            on failure, the first ``failed_at`` log ID.
        """
        rows = list(
            self._session.exec(
                select(AuditLogRecord)
                .where(AuditLogRecord.tenant_id == self._ctx.tenant_id)
                .order_by(AuditLogRecord.id.asc())
            ).all()
        )
        prev = "genesis"
        for row in rows:
            body = {
                "tenant_id": row.tenant_id,
                "event_type": row.event_type,
                "actor": row.actor,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "payload": row.payload,
                "correlation_id": row.correlation_id,
            }
            expected = chain_hash(prev, json.dumps(body, sort_keys=True, separators=(",", ":")))
            if expected != row.row_hash or row.prev_hash != prev:
                return {"verified": False, "failed_at": row.log_id, "rows": len(rows)}
            prev = row.row_hash
        return {"verified": True, "rows": len(rows), "tenant_id": self._ctx.tenant_id}
