"""Platform health summary."""

from __future__ import annotations

from typing import Any

from src.platform_core import SCHEMA_VERSION


def health_payload() -> dict[str, Any]:
    """Return health payload.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        Reads data from the requested source.
    """
    return {
        "status": "ok",
        "service": "endpoint-reliability-decision-platform",
        "schema_version": SCHEMA_VERSION,
        "dry_run_default": True,
    }
