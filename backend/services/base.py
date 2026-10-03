"""Shared tenant context and service utilities."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException
from sqlmodel import Session, select

from backend.auth.rbac import V1Principal, V1Role
from backend.db.models import TenantRecord


@dataclass(frozen=True)
class TenantContext:
    """Represent tenant context data used by the toolkit.

    Attributes:
        tenant_id: Field or variant describing tenant id evidence or state.
        actor_id: Field or variant describing actor id evidence or state.
        role: Field or variant describing role evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    tenant_id: str
    actor_id: str
    role: V1Role


def assert_tenant_access(principal: V1Principal, tenant_id: str) -> None:
    """Operators may only access their bound tenant unless admin."""
    if principal.role == V1Role.ADMIN:
        return
    if principal.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="tenant access denied")


def ensure_tenant(
    session: Session, tenant_id: str, *, display_name: str | None = None
) -> TenantRecord:
    """Ensure tenant.

    Args:
        session: Database session used to read or persist records.
        tenant_id: The tenant id value supplied by the caller.
        display_name: The display name value supplied by the caller.

    Returns:
        The TenantRecord result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    row = session.exec(select(TenantRecord).where(TenantRecord.tenant_id == tenant_id)).first()
    if row:
        return row
    tenant = TenantRecord(
        tenant_id=tenant_id,
        display_name=display_name or tenant_id,
        status="active",
    )
    session.add(tenant)
    session.flush()
    return tenant


def principal_context(principal: V1Principal) -> TenantContext:
    """Principal context.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        The TenantContext result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return TenantContext(
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        role=principal.role,
    )
