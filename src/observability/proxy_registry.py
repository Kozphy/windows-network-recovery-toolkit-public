"""Read-only HKCU proxy registry snapshot (re-export for observability layer)."""

from __future__ import annotations

from ..proxy_guard.registry import read_proxy_registry

__all__ = ["read_proxy_registry"]
