"""FastAPI dependencies for /v1 demo auth."""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import Header, HTTPException

from backend.auth.rbac import V1Principal, parse_role


def get_v1_principal(
    x_api_role: Annotated[str | None, Header(alias="X-Api-Role")] = None,
    x_api_token: Annotated[str | None, Header(alias="X-Api-Token")] = None,
    x_api_tenant: Annotated[str | None, Header(alias="X-Api-Tenant")] = None,
) -> V1Principal:
    """Get v1 principal.
    
    Args:
        x_api_role: The x api role value supplied by the caller.
        x_api_token: The x api token value supplied by the caller.
        x_api_tenant: The x api tenant value supplied by the caller.
    
    Returns:
        The V1Principal result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    expected = os.getenv("TRISK_API_TOKEN", "dev-trisk-token")
    if not x_api_token or x_api_token != expected:
        raise HTTPException(status_code=401, detail="invalid or missing X-Api-Token")
    role = parse_role(x_api_role)
    actor = os.getenv("TRISK_DEFAULT_ACTOR", "api-client")
    tenant = (x_api_tenant or os.getenv("TRISK_DEFAULT_TENANT", "default")).strip()
    return V1Principal(actor_id=actor, role=role, tenant_id=tenant)
