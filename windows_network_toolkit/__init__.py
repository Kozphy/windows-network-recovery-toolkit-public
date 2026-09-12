"""Endpoint Reliability Decision Platform — portfolio-facing Windows toolkit facade.

Module responsibility:
    Public package surface: ``SERVICE_NAME`` and ``__version__`` for health endpoints
    and CLI banners.

System placement:
    Top-level package for ``python -m windows_network_toolkit`` CLI and FastAPI ERP
    routes. Implementation modules live under ``windows_network_toolkit/``.

Key invariants:
    Technology Risk & Control Analytics for endpoint proxy reliability — not
    antivirus, EDR, or autonomous remediation.
"""

from __future__ import annotations

from windows_network_toolkit._version import resolve_version

__version__ = resolve_version()
SERVICE_NAME = "endpoint-reliability-decision-platform"

__all__ = ["SERVICE_NAME", "__version__"]
