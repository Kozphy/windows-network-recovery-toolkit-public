"""Platform API authentication: demo RBAC headers plus optional API key."""

from __future__ import annotations

from typing import Annotated

from fastapi import Header, HTTPException, status

from platform_core.rbac import DemoPrincipal, parse_demo_principal
from platform_core.settings import get_settings


def get_platform_principal(
    x_operator_id: Annotated[str | None, Header(alias="X-Operator-Id")] = None,
    x_operator_role: Annotated[str | None, Header(alias="X-Operator-Role")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> DemoPrincipal:
    """Resolve operator identity from RBAC headers or Bearer API key."""
    api_key = get_settings().resolved_api_key()
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if api_key and token == api_key:
            return parse_demo_principal("api-key-client", "admin")
        if api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid platform API key",
            )
    return parse_demo_principal(
        x_operator_id or "anonymous",
        x_operator_role or "viewer",
    )
