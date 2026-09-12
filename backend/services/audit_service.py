"""Audit Service — hash-chained audit logs with tenant isolation."""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlmodel import Session, select

from backend.db.models import AuditLogRecord
from backend.services.base import TenantContext, ensure_tenant
from src.platform_core.governance.chain_of_custody import chain_hash


class AuditService:
    """Represent audit service data used by the toolkit.
    
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

    def _last_hash(self) -> str:
        row = self._session.exec(
            select(AuditLogRecord)
            .where(AuditLogRecord.tenant_id == self._ctx.tenant_id)
            .order_by(AuditLogRecord.id.desc())
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
        """Append.
        
        Args:
            event_type: The event type value supplied by the caller.
            resource_type: The resource type value supplied by the caller.
            resource_id: The resource id value supplied by the caller.
            payload: Request or domain payload supplied by the caller.
            correlation_id: The correlation id value supplied by the caller.
        
        Returns:
            The AuditLogRecord result produced by the operation.
        
        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
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

    def list_logs(self, *, limit: int = 50, correlation_id: str | None = None) -> list[AuditLogRecord]:
        """List logs.
        
        Args:
            limit: The limit value supplied by the caller.
            correlation_id: The correlation id value supplied by the caller.
        
        Returns:
            The list[AuditLogRecord] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        q = select(AuditLogRecord).where(AuditLogRecord.tenant_id == self._ctx.tenant_id)
        if correlation_id:
            q = q.where(AuditLogRecord.correlation_id == correlation_id)
        q = q.order_by(AuditLogRecord.created_at.desc()).limit(limit)
        return list(self._session.exec(q).all())

    def verify_chain(self) -> dict[str, Any]:
        """Verify chain.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
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
