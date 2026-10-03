"""Summaries for operator reports — pure aggregation over events + default profile."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..proxy_guard.snapshot_capture import capture_proxy_snapshot
from .diff_engine import drift_bundle
from .paths import events_jsonl, policy_json
from .policy import NetworkStatePolicy
from .snapshot_store import load_default_record, snapshot_from_record


def _parse_since_hours(since: str) -> float:
    s = since.strip().lower()
    m = re.match(r"^(\d+)\s*h(?:ours?)?$", s)
    if m:
        return float(m.group(1))
    m = re.match(r"^(\d+)\s*d(?:ays?)?$", s)
    if m:
        return float(m.group(1)) * 24
    m = re.match(r"^(\d+)\s*m(?:in(?:utes)?)?$", s)
    if m:
        return float(m.group(1)) / 60.0
    m = re.match(r"^(\d+)$", s)
    if m:
        return float(m.group(1))  # bare number = hours
    return 24.0


def _parse_iso(ts: str) -> datetime | None:
    t = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        return None


def iter_recent_events(repo_root: Path, since: str) -> list[dict[str, Any]]:
    """Iter recent events.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.
        since: The since value supplied by the caller.

    Returns:
        The list[dict[str, Any]] result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    path = events_jsonl(repo_root)
    if not path.is_file():
        return []
    hours = _parse_since_hours(since)
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            ts_s = str(obj.get("timestamp_utc") or "")
            ts = _parse_iso(ts_s)
            if ts is None or ts >= cutoff:
                rows.append(obj)
    return rows


def build_network_state_report(
    repo_root: Path,
    *,
    since: str,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Aggregate events and current drift versus default profile (when present)."""

    run_fn = run or subprocess.run

    events = iter_recent_events(repo_root, since)
    proxy_changes = sum(1 for e in events if e.get("event_type") == "drift_detected")
    loopback_events = sum(
        1
        for e in events
        if e.get("event_type") == "drift_detected"
        and isinstance(e.get("payload"), dict)
        and any(
            "loopback" in str(x).lower()
            for x in (e["payload"].get("suspicious_cases") or [])
            + (e["payload"].get("suspicious_loopback_hints") or [])
        )
    )

    policy = NetworkStatePolicy.from_file(policy_json(repo_root))

    default_meta = load_default_record(repo_root)
    default_snap = snapshot_from_record(default_meta) if default_meta else None

    drift_status = "unknown"
    diff_summary: dict[str, Any] | None = None
    recommended_next = "Save a baseline: python -m src network-state snapshot save --name <profile>"

    if default_snap is not None:
        try:
            try:
                current = capture_proxy_snapshot(run=run_fn, skip_optional_cli=True)
            except (OSError, TypeError, RuntimeError):
                current = capture_proxy_snapshot(run=run_fn)
        except Exception:
            drift_status = "capture_unavailable"
            diff_summary = None
            recommended_next = (
                "Run drift check on Windows: python -m src network-state diff --default"
            )
        else:
            diff_summary = drift_bundle(
                default_snap,
                current,
                policy=policy,
                attribution_heuristic=None,
            )
            drift_status = "in_sync" if not diff_summary.get("changed_fields") else "drifted"
            if diff_summary.get("suspicious_cases"):
                recommended_next = (
                    "Review drift; run: python -m src network-state diff --default --json"
                )
            elif drift_status == "drifted":
                recommended_next = "Compare profiles: python -m src network-state diff --default"
            else:
                recommended_next = "Continue monitoring or capture another named profile."

    actors_note = (
        "Attach proxy-attribution for candidate actors when investigating (heuristic-only)."
    )

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "window": since,
        "event_totals": {
            "proxy_drift_signals": proxy_changes,
            "suspicious_loopback_signals": loopback_events,
            "events_ingested": len(events),
        },
        "default_profile_name": (default_meta or {}).get("name"),
        "drift_vs_default": drift_status,
        "diff_vs_default_summary": diff_summary,
        "last_policy_hint": (diff_summary or {}).get("policy") if diff_summary else None,
        "attribution_note": actors_note,
        "recommended_next_action": recommended_next,
    }
