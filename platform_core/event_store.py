"""Unified append-only event store under ``logs/`` (backward compatible with legacy JSONL).

Module responsibility:
    Write timeline rows for observations/events, policy decisions, and remediation previews.
    Support offline replay assembly by ``run_id`` without subprocess probes.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from platform_core.models import utc_now_iso

EVENTS_JSONL = "logs/events.jsonl"
DECISIONS_JSONL = "logs/decisions.jsonl"
REMEDIATION_PREVIEWS_JSONL = "logs/remediation_previews.jsonl"
SCHEMA_VERSION = "platform_event_store.v1"


def _append(repo_root: Path, rel_path: str, payload: dict[str, Any]) -> Path:
    path = repo_root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return path


def append_event(
    repo_root: Path,
    *,
    run_id: str,
    event_type: str,
    payload: dict[str, Any] | None = None,
    actor: str = "python -m src",
    evidence_level: str = "observed",
) -> Path:
    """Append one timeline event row."""
    return _append(
        repo_root,
        EVENTS_JSONL,
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "platform_event",
            "timestamp": utc_now_iso(),
            "run_id": run_id,
            "event_type": event_type,
            "actor": actor,
            "evidence_level": evidence_level,
            "payload": payload or {},
        },
    )


def append_decision(
    repo_root: Path,
    *,
    run_id: str,
    decision: str,
    reason_codes: list[str],
    payload: dict[str, Any] | None = None,
    blocked_actions: list[str] | None = None,
) -> Path:
    """Append one policy/decision row (mirrors live_run_audit for new consumers)."""
    return _append(
        repo_root,
        DECISIONS_JSONL,
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "platform_decision",
            "timestamp": utc_now_iso(),
            "run_id": run_id,
            "decision": decision,
            "reason_codes": list(reason_codes),
            "blocked_actions": list(blocked_actions or []),
            "payload": payload or {},
        },
    )


def append_remediation_preview(
    repo_root: Path,
    *,
    run_id: str,
    action_id: str,
    policy: str,
    dry_run: bool = True,
    detail: str = "",
) -> Path:
    """Append remediation preview row (never implies execution)."""
    return _append(
        repo_root,
        REMEDIATION_PREVIEWS_JSONL,
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "remediation_preview",
            "timestamp": utc_now_iso(),
            "run_id": run_id,
            "action_id": action_id,
            "policy": policy,
            "dry_run": dry_run,
            "detail": detail,
        },
    )


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            yield row


def find_decision_row(repo_root: Path, run_id: str) -> dict[str, Any] | None:
    """Find last decision row for ``run_id`` in unified or legacy logs."""
    rid = run_id.strip()
    for rel in (DECISIONS_JSONL, "logs/decision_runs.jsonl"):
        path = repo_root / rel
        if not path.is_file():
            continue
        last: dict[str, Any] | None = None
        for row in _iter_jsonl(path):
            key = str(row.get("run_id") or row.get("diagnosis_id") or "")
            if key == rid:
                last = row
        if last is not None:
            return last
    return None


def replay_timeline(repo_root: Path, run_id: str) -> dict[str, Any]:
    """Assemble events + decision for a run without live probes."""
    rid = run_id.strip()
    events = [r for r in _iter_jsonl(repo_root / EVENTS_JSONL) if str(r.get("run_id")) == rid]
    decision = find_decision_row(repo_root, rid)
    previews = [
        r
        for r in _iter_jsonl(repo_root / REMEDIATION_PREVIEWS_JSONL)
        if str(r.get("run_id")) == rid
    ]
    return {
        "run_id": rid,
        "events": events,
        "decision": decision,
        "remediation_previews": previews,
        "replay_mode": "read_only_no_probes",
    }


def record_live_diagnosis_run(
    repo_root: Path,
    *,
    run_id: str,
    observations: dict[str, Any],
    hypothesis_decisions: list[dict[str, Any]],
    primary_decision: dict[str, Any] | None = None,
) -> None:
    """Mirror a live diagnose row into unified event store (additive)."""
    append_event(
        repo_root,
        run_id=run_id,
        event_type="diagnosis_live_completed",
        payload={"observation_keys": sorted(observations.keys()) if observations else []},
        evidence_level="observed",
    )
    primary = primary_decision or (hypothesis_decisions[0] if hypothesis_decisions else {})
    append_decision(
        repo_root,
        run_id=run_id,
        decision=str(primary.get("decision") or "PREVIEW"),
        reason_codes=list(primary.get("reason_codes") or []),
        blocked_actions=list(primary.get("blocked_actions") or []),
        payload={
            "proof_status": primary.get("proof_status"),
            "hypothesis": primary.get("hypothesis"),
            "confidence": primary.get("confidence"),
            "hypothesis_decisions": hypothesis_decisions,
        },
    )
