"""Multi-tenant isolation — row-level and API-level enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from fastapi import HTTPException

TenantRole = Literal[
    "tenant_viewer",
    "tenant_operator",
    "tenant_admin",
    "tenant_security_auditor",
    "platform_admin",
]


@dataclass(frozen=True)
class TenantPrincipal:
    """JWT-derived principal with tenant scope (production)."""

    subject: str
    tenant_id: str
    roles: frozenset[str]
    org_id: str = ""

    def has_role(self, role: TenantRole) -> bool:
        """Evaluate the has role condition.

        Args:
            role: Value supplied by the caller for role.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return role in self.roles or "platform_admin" in self.roles


@dataclass
class TenantIsolationPolicy:
    """Enforce blast-radius boundaries between tenants."""

    allow_cross_tenant_read: bool = False
    allow_cross_tenant_replay: bool = False
    max_endpoints_per_tenant: int = 150_000
    max_ingest_rps_per_tenant: int = 500


def assert_tenant_access(
    principal: TenantPrincipal,
    resource_tenant_id: str,
    *,
    action: Literal["read", "write", "replay", "admin"] = "read",
) -> None:
    """Fail closed on tenant boundary violation."""
    if "platform_admin" in principal.roles:
        return
    if principal.tenant_id != resource_tenant_id:
        raise HTTPException(status_code=403, detail="tenant_boundary_violation")

    role_map = {
        "read": ("tenant_viewer", "tenant_operator", "tenant_admin", "tenant_security_auditor"),
        "write": ("tenant_operator", "tenant_admin"),
        "replay": ("tenant_admin", "tenant_security_auditor"),
        "admin": ("tenant_admin",),
    }
    allowed = role_map.get(action, ())
    if not any(r in principal.roles for r in allowed):
        raise HTTPException(status_code=403, detail=f"tenant_rbac_denied:{action}")
