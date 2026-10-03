"""Asset models for technology risk context."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class Asset(BaseModel):
    """Represent the asset type.

    Key fields:
        asset_id: Structured value carried by this type.
        name: Structured value carried by this type.
        asset_type: Structured value carried by this type.
        criticality: Structured value carried by this type.
        owner: Structured value carried by this type.
        description: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    asset_id: str
    name: str
    asset_type: str
    criticality: str = "high"
    owner: str = "Endpoint Engineering"
    description: str = ""


def asset_for_fixture(fixture: dict[str, Any]) -> Asset:
    """Return asset for fixture.

    Args:
        fixture: fixture supplied by the caller.

    Returns:
        The computed `Asset` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    override = fixture.get("asset")
    if override:
        return Asset.model_validate(override)
    state = fixture.get("proxy_state") or {}
    server = state.get("wininet_proxy_server") or "WinINET proxy configuration"
    return Asset(
        asset_id="ASSET_WININET_PROXY",
        name="Windows endpoint WinINET proxy settings",
        asset_type="endpoint_configuration",
        criticality="high",
        owner="IT Operations / Endpoint Engineering",
        description=f"HKCU Internet Settings proxy state (observed: {server})",
    )
