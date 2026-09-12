"""HKCU proxy state comparison and rollback verification helpers.

Contrast :class:`~src.proxy_guard.models.ProxySnapshot` probes with lightweight registry views
without mutating runtime configuration.

See Also:
    :mod:`~src.proxy_guard.wininet_change_diff` for operator-facing ``proxy-watch`` snapshot diffs keyed by
    canonical WinINET registry field labels.
"""

from __future__ import annotations

from typing import Any

from ..core.models import ProxyRegistrySnapshot
from .models import ProxySnapshot


def proxy_state_audit_dict(snapshot: ProxySnapshot | None) -> dict[str, Any]:
    """Project WinINET-aligned fields suitable for unified pipeline audit payloads."""
    if snapshot is None:
        return {
            "proxy_enable": None,
            "proxy_server": None,
            "auto_config_url": None,
            "auto_detect": None,
        }
    return {
        "proxy_enable": snapshot.proxy_enable,
        "proxy_server": snapshot.proxy_server,
        "auto_config_url": snapshot.auto_config_url,
        "auto_detect": snapshot.auto_detect,
    }


def hkcu_tuple_from_registry(reg: ProxyRegistrySnapshot) -> tuple[Any, Any, Any, Any]:
    """Comparable core tuple for rollback verification."""
    return (
        reg.proxy_enable,
        reg.proxy_server,
        reg.auto_config_url,
        reg.auto_detect,
    )


def hkcu_tuple_expected_from_snapshot(snapshot: ProxySnapshot) -> tuple[Any, Any, Any, Any]:
    """Expected observable HKCU equality target after rollback from ``snapshot``."""
    return (
        snapshot.proxy_enable,
        snapshot.proxy_server,
        snapshot.auto_config_url,
        snapshot.auto_detect,
    )


def verify_hkcu_core_matches_prior(
    observed: ProxyRegistrySnapshot,
    *,
    prior_target: ProxySnapshot,
) -> bool:
    """Return True when polled HKCU mirrors the prior snapshot core fields."""

    return hkcu_tuple_from_registry(observed) == hkcu_tuple_expected_from_snapshot(prior_target)


def wininet_argv_restored_fields(reg_rows_audit: list[dict[str, Any]]) -> list[str]:
    """Derive touched WinINET value names from flattened ``rollback`` audit rows."""

    fields: list[str] = []
    for row in reg_rows_audit:
        argv = row.get("argv") or []
        try:
            idx = None
            for marker in ("-v", "/v"):
                if marker in argv:
                    idx = argv.index(marker)
                    break
            if idx is None:
                continue
            if idx + 1 < len(argv):
                name = argv[idx + 1]
                if isinstance(name, str) and name not in fields:
                    fields.append(name)
        except (TypeError, ValueError):
            continue
    return fields
