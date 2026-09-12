"""Compatibility shim exporting legacy Proxy Guard control entrypoints.

Module responsibility:
    Re-export :func:`service.run_proxy_guard_from_legacy` as ``run_proxy_guard_control``
    for historical import paths and pytest doubles.

System placement:
    Thin facade over :mod:`service`; new code should import :mod:`service` or invoke
    ``python -m src proxy-guard`` directly.

Side effects:
    Delegates entirely to :mod:`service` — see that module for audit/mutation behavior.
"""

from __future__ import annotations

from .service import run_proxy_guard_from_legacy as run_proxy_guard_control

__all__ = ["run_proxy_guard_control"]
