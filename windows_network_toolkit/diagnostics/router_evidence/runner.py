"""Router evidence import and correlation runners.

Module responsibility:
    Orchestrate import → JSONL normalize and host/router correlation CLI backends.

System placement:
    Invoked by ``router-import``, ``router-correlate`` CLI and optional ``lan_privacy.runner``.

Key invariants:
    * Unknown ``import_type`` returns structured error without writing output.
    * ``load_router_jsonl`` skips missing files and malformed lines silently.
    * Correlation loads lan-watch JSONL when host observations path not supplied.

Side effects:
    * Writes normalized router JSONL via ``normalizer.write_router_jsonl``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .correlator import correlate_host_router
from .importers import IMPORTERS
from .models import ROUTER_SCHEMA
from .normalizer import write_router_jsonl


def run_router_import(
    *,
    import_type: str,
    input_path: str,
    out_path: str,
    inject: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Import a router log file and write normalized events to a JSONL file.

    Args:
        import_type: Log format key — one of ``"dns"``, ``"firewall"``,
            ``"dhcp"``, or ``"devices"``.
        input_path: Path to the raw router log file.
        out_path: Destination JSONL file path for normalized output.
        inject: When supplied, passed directly to the importer bypassing disk I/O
            (for testing).

    Returns:
        Result dict from ``write_router_jsonl`` enriched with ``import_type``,
        or ``{"ok": False, "error": ...}`` for an unknown ``import_type``.
    """
    importer = IMPORTERS.get(import_type)
    if not importer:
        return {"ok": False, "error": f"Unknown import type: {import_type}"}
    events = importer(Path(input_path), inject=inject)
    result = write_router_jsonl(events, Path(out_path))
    result["import_type"] = import_type
    return result


def load_router_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Load a normalized router-evidence JSONL file into a list of event dicts.

    Skips missing files and malformed lines silently.

    Args:
        path: Filesystem path to a normalized router JSONL file produced by
            ``run_router_import``.

    Returns:
        List of parsed event dicts in file order.  Empty list when the file does
        not exist or contains no valid JSON lines.
    """
    events: list[dict[str, Any]] = []
    p = Path(path)
    if not p.is_file():
        return events
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def run_router_correlation(
    *,
    host_log: str,
    router_log: str,
) -> dict[str, Any]:
    """Correlate host lan-watch observations with normalized router evidence.

    Loads the host JSONL (lan-watch) and router JSONL, converts host events
    to ``LanObservation`` dicts, then calls ``correlate_host_router`` to join
    on IP/MAC.

    Args:
        host_log: Path to a ``lan-watch.jsonl`` file produced by ``run_lan_watch``.
        router_log: Path to a normalized router JSONL file produced by
            ``run_router_import``.

    Returns:
        Dict tagged ``ROUTER_SCHEMA`` with ``host_observation_count``,
        ``router_event_count``, and the nested ``correlation`` result from
        ``correlate_host_router``.
    """
    from windows_network_toolkit.diagnostics.lan_privacy.collectors import (
        observations_from_watch_events,
    )
    from windows_network_toolkit.diagnostics.lan_privacy.watch import load_watch_jsonl

    host_events = load_watch_jsonl(host_log)
    observations = observations_from_watch_events(host_events)
    devices = host_events[-1].get("devices", []) if host_events else []
    router_events = load_router_jsonl(router_log)
    correlation = correlate_host_router(observations, router_events, devices)
    return {
        "schema_version": ROUTER_SCHEMA,
        "host_observation_count": len(observations),
        "router_event_count": len(router_events),
        "correlation": correlation,
    }
