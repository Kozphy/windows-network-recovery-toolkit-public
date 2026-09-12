"""Aggregate reliability KPI counters from local toolkit ``logs/`` JSONL shards.

Module responsibility:
    Scan ``logs/events.jsonl``, ``logs/decisions.jsonl``,
    ``logs/remediation_previews.jsonl``, and ``logs/order_flow_audit.jsonl`` under a
    repo root and return portfolio-friendly counters.

System placement:
    Used by tests and optional dashboard merges; read-only — never mutates log files.

Input assumptions:
    JSONL lines are UTF-8; malformed lines skipped via :func:`platform_core.storage.iter_jsonl`.

Output guarantees:
    Dict with integer counters and optional ``order_flow_event_latency_ms_avg``; missing
    files contribute zero counts (not errors).

Timezone:
    Not applicable — counts rows only, does not parse event timestamps for windows.

Failure modes:
    Partially written last lines may be skipped by tolerant readers; metrics may lag
    live writers by one append.

Audit Notes:
    ``proof_inconclusive_count`` tracks ``HIGH_CONFIDENCE_UNPROVEN`` in decision rows;
    use alongside policy regression tests in ``tests/test_policy_v2_regression.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from platform_core.event_store import DECISIONS_JSONL, EVENTS_JSONL, REMEDIATION_PREVIEWS_JSONL
from platform_core.storage import iter_jsonl


def compute_toolkit_metrics(repo_root: Path) -> dict[str, Any]:
    """Aggregate counters for portfolio dashboards / tests."""
    root = repo_root.resolve()
    events_path = root / EVENTS_JSONL
    decisions_path = root / DECISIONS_JSONL
    previews_path = root / REMEDIATION_PREVIEWS_JSONL
    order_path = root / "logs" / "order_flow_audit.jsonl"

    event_count = 0
    decision_count = 0
    preview_count = 0
    proof_inconclusive = 0
    remediation_blocked = 0
    invalid_transition_count = 0
    latency_samples: list[float] = []

    if events_path.is_file():
        for _row in iter_jsonl(events_path):
            event_count += 1

    if decisions_path.is_file():
        for row in iter_jsonl(decisions_path):
            decision_count += 1
            codes = row.get("reason_codes") or []
            if isinstance(codes, list) and "HIGH_CONFIDENCE_UNPROVEN" in codes:
                proof_inconclusive += 1
            if str(row.get("decision") or "") == "BLOCK":
                remediation_blocked += 1

    if previews_path.is_file():
        for _ in iter_jsonl(previews_path):
            preview_count += 1

    if order_path.is_file():
        for row in iter_jsonl(order_path):
            if row.get("valid") is False:
                invalid_transition_count += 1
            lat = row.get("latency_ms")
            if isinstance(lat, (int, float)):
                latency_samples.append(float(lat))

    avg_latency = round(sum(latency_samples) / len(latency_samples), 4) if latency_samples else None

    return {
        "event_count": event_count,
        "decision_count": decision_count,
        "remediation_preview_count": preview_count,
        "proof_inconclusive_count": proof_inconclusive,
        "remediation_blocked_count": remediation_blocked,
        "invalid_transition_count": invalid_transition_count,
        "order_flow_event_latency_ms_avg": avg_latency,
        "queue_depth": 0,
        "error_rate": 0.0,
        "retry_count": 0,
    }
