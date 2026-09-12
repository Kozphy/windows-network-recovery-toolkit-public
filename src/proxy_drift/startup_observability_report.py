"""Summarize startup observability logs for operators."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def summarize_boot_trace(trace_path: Path) -> dict[str, Any]:
    """Summarize existing boot trace JSONL observations.

    Args:
        trace_path: Path to a boot trace JSONL file.

    Returns:
        Dict with sample count, first/final proxy state, observed delta events, recommended next step, and limitations.

    Side effects:
        Reads the trace file when it exists; ignores malformed JSONL rows.

    Audit Notes:
        Summary is observational and does not prove registry writer identity."""
    rows = []
    if trace_path.exists():
        for line in trace_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not rows:
        return {
            "schema_version": "startup_observability_report.v1",
            "timestamp_utc": _now(),
            "trace_path": str(trace_path),
            "samples": 0,
            "reason": "No valid boot trace samples found.",
            "limitations": [
                "Summary depends on existing boot trace JSONL samples.",
            ],
        }
    first = rows[0]
    last = rows[-1]
    deltas = []
    for row in rows:
        deltas.extend(row.get("delta_events") or [])
    return {
        "schema_version": "startup_observability_report.v1",
        "timestamp_utc": _now(),
        "trace_path": str(trace_path),
        "samples": len(rows),
        "first_observed_proxy_enable": (first.get("wininet") or {}).get("proxy_enable"),
        "first_observed_proxy_server": (first.get("wininet") or {}).get("proxy_server"),
        "final_proxy_enable": (last.get("wininet") or {}).get("proxy_enable"),
        "final_proxy_server": (last.get("wininet") or {}).get("proxy_server"),
        "final_classification": ((last.get("classification") or {}).get("classification")),
        "listener_found_final": last.get("listener_found"),
        "delta_events_seen": sorted(set(str(x) for x in deltas)),
        "recommended_next_step": "Inspect startup items and listener attribution if proxy_server_changed or listener_appeared is present.",
        "limitations": [
            "Summary is observational and does not prove registry writer identity.",
        ],
    }
