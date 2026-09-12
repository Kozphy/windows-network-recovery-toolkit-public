"""LAN watch — poll neighbors and append JSONL observations (read-only).

Module responsibility:
    Periodically collect inventory/mDNS deltas and append structured watch events to
    local JSONL for later classification and correlation.

System placement:
    Invoked by ``lan-watch`` CLI and loaded by ``runner`` / ``router_evidence`` pipelines.

Key invariants:
    * Read-only collection — no neighbor table or firewall mutation.
    * Default audit path ``.audit/lan-watch.jsonl``; callers may override.
    * New-neighbor and mDNS deltas become ``LanObservation``-compatible rows.

Side effects:
    * Appends JSONL rows to the configured audit path during each poll cycle.

Audit Notes:
    Watch JSONL is input evidence for classify/risk/correlate — preserve append order
    and avoid manual edits that break event continuity.
"""

from __future__ import annotations

import json
import platform
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .collectors import collect_inventory, collect_mdns_summary
from .models import SCHEMA_VERSION

DEFAULT_AUDIT_PATH = ".audit/lan-watch.jsonl"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _diff_neighbors(
    prev: dict[str, dict[str, Any]],
    curr: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for dev in curr:
        ip = dev.get("ip", "")
        mac = dev.get("mac", "")
        if ip not in prev:
            observations.append(
                {
                    "protocol": "ARP",
                    "source_ip": ip,
                    "source_mac": mac,
                    "target_ip": "",
                    "direction": "broadcast",
                    "evidence_source": "HOST_LEVEL_OBSERVATION",
                    "note": "new_neighbor_observed",
                }
            )
        elif prev[ip].get("mac") != mac and mac:
            observations.append(
                {
                    "protocol": "ARP",
                    "source_ip": ip,
                    "source_mac": mac,
                    "target_ip": "",
                    "direction": "broadcast",
                    "evidence_source": "HOST_LEVEL_OBSERVATION",
                    "note": "mac_change_observed",
                }
            )
    return observations


def run_lan_watch(
    *,
    duration: int = 60,
    interval: float = 10.0,
    audit_path: str = DEFAULT_AUDIT_PATH,
    inject_sequence: list[dict[str, Any]] | None = None,
    include_mdns: bool = False,
    mdns_duration: float = 2.0,
) -> dict[str, Any]:
    """Poll LAN neighbors at regular intervals and append observations to JSONL.

    Each poll tick collects the neighbor/ARP inventory, diffs against the previous
    snapshot to detect new or MAC-changed neighbors, and optionally collects mDNS
    observations.  Each tick's event is appended to ``audit_path`` as a JSONL row.

    Args:
        duration: Total watch duration in seconds (minimum 1).
        interval: Polling interval in seconds between ticks.
        audit_path: Path to the output JSONL file.  Parent directories are created
            if they do not exist.
        inject_sequence: When supplied, each element is used as the ``inject``
            argument for successive ``collect_inventory`` calls, bypassing live I/O.
            Enables deterministic test replay.
        include_mdns: When ``True``, also collects mDNS observations on each tick.
        mdns_duration: mDNS listening window per tick in seconds.

    Returns:
        Dict with ``ok`` (bool), ``schema_version``, ``audit_path``,
        ``events`` (list of tick event dicts), and ``limitations``.
        Returns immediately with ``"unsupported_platform": True`` on non-Windows
        when ``inject_sequence`` is not supplied.
    """
    if platform.system().lower() != "windows" and not inject_sequence:
        return {
            "ok": False,
            "unsupported_platform": True,
            "schema_version": SCHEMA_VERSION,
            "events": [],
            "limitations": ["lan-watch requires Windows or --fixture inject_sequence."],
        }

    events: list[dict[str, Any]] = []
    prev_neighbors: dict[str, dict[str, Any]] = {}
    path = Path(audit_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def _tick(tick_inject: dict[str, Any] | None = None) -> dict[str, Any]:
        nonlocal prev_neighbors
        inv = collect_inventory(inject=tick_inject)
        devices = inv.get("devices") or []
        observations = _diff_neighbors(prev_neighbors, devices)
        prev_neighbors = {d.get("ip", ""): d for d in devices if d.get("ip")}

        if include_mdns and not tick_inject:
            mdns = collect_mdns_summary(duration_seconds=mdns_duration)
            for b in mdns.get("broadcasters") or []:
                observations.append(
                    {
                        "protocol": "MDNS",
                        "source_ip": b.get("ip", ""),
                        "direction": "broadcast",
                        "evidence_source": "HOST_LEVEL_OBSERVATION",
                    }
                )

        event = {
            "event": "lan_watch_tick",
            "timestamp_utc": _now(),
            "device_count": len(devices),
            "observations": observations,
            "devices": devices,
            "limitations": inv.get("limitations") or [],
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        events.append(event)
        return event

    if inject_sequence:
        for tick in inject_sequence:
            events.append(_tick(tick))
        return {
            "ok": True,
            "schema_version": SCHEMA_VERSION,
            "audit_path": str(path),
            "events": events,
            "limitations": ["Fixture replay — not live network capture."],
        }

    end = time.time() + max(duration, 1)
    while time.time() < end:
        _tick()
        remaining = end - time.time()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "audit_path": str(path),
        "events": events,
        "limitations": [
            "Host-level observation only — cannot confirm cross-host traffic without router evidence.",
        ],
    }


def load_watch_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Load a lan-watch JSONL file into a list of event dicts.

    Skips missing files silently and ignores malformed (non-JSON) lines.

    Args:
        path: Filesystem path to a ``lan-watch.jsonl`` file.

    Returns:
        List of parsed event dicts in append order.  Empty list when the file
        does not exist or contains no valid JSON lines.
    """
    events: list[dict[str, Any]] = []
    p = Path(path)
    if not p.is_file():
        return events
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
