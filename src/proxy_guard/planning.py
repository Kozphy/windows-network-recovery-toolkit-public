"""Pure helpers for registry views and comparisons (no I/O)."""

from __future__ import annotations

import json
from typing import Any


def normalize_registry_view(reg_dict: dict[str, Any], parsed_dict: dict[str, Any]) -> dict[str, Any]:
    """Merge raw HKCU fields with parser output (stable JSON compare)."""
    return {
        "proxy_enable": reg_dict.get("proxy_enable"),
        "proxy_server": reg_dict.get("proxy_server"),
        "proxy_override": reg_dict.get("proxy_override"),
        "auto_config_url": reg_dict.get("auto_config_url"),
        "auto_detect": reg_dict.get("auto_detect"),
        "parsed": parsed_dict,
    }


def registry_views_equal(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Stable equality for polling loops."""
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def listen_port_for_attribution(parsed: Any) -> int | None:
    """Pick a single localhost listen port for netstat correlation."""
    if parsed.localhost_port is not None:
        return int(parsed.localhost_port)
    if parsed.http_localhost_port is not None:
        return int(parsed.http_localhost_port)
    if parsed.https_localhost_port is not None:
        return int(parsed.https_localhost_port)
    if parsed.socks_port is not None:
        return int(parsed.socks_port)
    return None
