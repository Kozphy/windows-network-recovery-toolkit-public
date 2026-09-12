"""Deterministic replay of proxy-watch JSONL fixtures through the state machine.

Module responsibility:
    Load proxy-watch JSONL, normalize rows, coalesce flapping, classify transitions,
    detect reverter loops, and run proxy-watch control tests — without host mutation.

System placement:
    Backing implementation for ``cli proxy-replay`` and portfolio replay demos.

Key invariants:
    * Pure replay — no registry reads/writes on fixture input.
    * Same input rows + ``coalesce_ms`` yield stable output (see CTRL_AUDIT_REPLAY_DETERMINISM).

Side effects:
    Optional JSON write when ``replay_proxy_file`` is called with ``output`` stream.

Failure modes:
    Invalid JSONL lines raise ``json.JSONDecodeError``.
    Empty input yields zero-length event lists with NOT_TESTED controls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from windows_network_toolkit.proxy_state_machine import (
    TransitionClass,
    build_proxy_evidence_event,
    coalesce_proxy_events,
    detect_reverter_loop_pattern,
    merge_coalesced_states,
)
from windows_network_toolkit.proxy_watch_controls import run_proxy_watch_control_tests


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _extract_transition_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize JSONL rows into transition inputs."""
    out: list[dict[str, Any]] = []
    for row in rows:
        if row.get("event") == "proxy_change":
            out.append(
                {
                    "timestamp_utc": row.get("timestamp_utc"),
                    "before": row.get("old_state") or row.get("before"),
                    "after": row.get("new_state") or row.get("after"),
                    "owner": row.get("owner"),
                    "listener": row.get("owner"),
                }
            )
            continue
        if "before_state" in row and "after_state" in row:
            out.append(row)
            continue
        if "before" in row and "after" in row:
            out.append(row)
            continue
        if "ProxyEnable" in row or "wininet_proxy_enabled" in row:
            out.append(row)
    return out


def replay_proxy_events(
    rows: list[dict[str, Any]],
    *,
    coalesce_ms: int = 1000,
) -> dict[str, Any]:
    """Replay historical proxy events with coalescing and classification.

    Args:
        rows: JSONL-derived dict rows (proxy_change, before/after, or raw state rows).
        coalesce_ms: Coalesce window passed to ``coalesce_proxy_events``.

    Returns:
        Dict with ``summary``, classified ``events``, and ``controls`` from
        ``run_proxy_watch_control_tests``.

    Side effects:
        None.
    """
    transitions = _extract_transition_rows(rows)
    if not transitions and rows:
        transitions = rows

    coalesced = coalesce_proxy_events(transitions, coalesce_window_ms=coalesce_ms)

    classified: list[dict[str, Any]] = []
    for item in coalesced:
        if "transition_class" in item and "before_state" in item:
            classified.append(item)
            continue
        before, after, raw_sub = merge_coalesced_states([item]) if item.get("coalesced") else (
            item.get("before") or item.get("before_state") or {},
            item.get("after") or item.get("after_state") or {},
            [],
        )
        if item.get("coalesced") and item.get("raw_sub_events"):
            before, after, raw_sub = merge_coalesced_states(
                [{"before": s.get("before"), "after": s.get("after"), **s} for s in item["raw_sub_events"]]
            )
        evidence = build_proxy_evidence_event(
            before_raw=before,
            after_raw=after,
            timestamp_utc=str(item.get("timestamp_utc") or ""),
            listener=item.get("owner") or item.get("listener"),
            coalesce_meta={
                "coalesced": bool(item.get("coalesced")),
                "coalesce_window_ms": item.get("coalesce_window_ms", coalesce_ms),
                "raw_sub_event_count": item.get("raw_sub_event_count", 1),
            },
            raw_sub_events=item.get("raw_sub_events") or raw_sub or None,
        )
        classified.append(evidence)

    loop = detect_reverter_loop_pattern(classified)
    if loop == TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP and classified:
        last = dict(classified[-1])
        last["transition_class"] = str(loop)
        last["recommended_action"] = (
            "require human review — pattern suggests a proxy reverter or auto-reapply loop; "
            "this is correlation, not proof of registry write"
        )
        last["limitations"] = [
            "Pattern suggests a proxy reverter or auto-reapply loop",
            "This is correlation, not proof of registry write",
            "Collect Sysmon Event ID 13 or Procmon trace for registry writer proof",
        ]
        last["risk"] = "HIGH"
        last["policy_decision"] = "REQUIRE_HUMAN_REVIEW"
        classified[-1] = last

    controls = run_proxy_watch_control_tests(events=classified, coalesce_ms=coalesce_ms)

    summary = {
        "input_event_count": len(rows),
        "transition_count": len(transitions),
        "coalesced_event_count": len(classified),
        "coalesce_window_ms": coalesce_ms,
        "reverter_loop_detected": loop == TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP,
    }

    return {
        "summary": summary,
        "events": classified,
        "controls": controls,
    }


def replay_proxy_file(
    input_path: str | Path,
    *,
    coalesce_ms: int = 1000,
    output: TextIO | None = None,
) -> dict[str, Any]:
    """Load JSONL from disk and replay through the state machine.

    Args:
        input_path: Path to proxy-watch or transition fixture JSONL.
        coalesce_ms: Coalesce window in milliseconds.
        output: Optional text stream to write indented JSON payload.

    Returns:
        Same structure as ``replay_proxy_events``.

    Side effects:
        Reads file from disk; writes JSON to ``output`` when provided.
    """
    path = Path(input_path)
    rows = _load_jsonl(path)
    payload = replay_proxy_events(rows, coalesce_ms=coalesce_ms)
    if output is not None:
        json.dump(payload, output, indent=2)
        output.write("\n")
    return payload
