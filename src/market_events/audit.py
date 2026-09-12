"""Append-only JSONL audit for market event research commands."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..core.jsonl import append_jsonl
from ..core.time_utils import utc_now_iso
from .models import ResearchPolicyStatus


def canonical_json_hash(payload: Any) -> str:
    """Canonical json hash.
    
    Args:
        payload: Request or domain payload supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def default_audit_path(repo_root: Path | None = None) -> Path:
    """Default audit path.
    
    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.
    
    Returns:
        The Path result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    root = repo_root or Path.cwd()
    return root / "logs" / "market_events_audit.jsonl"


def append_market_audit(
    *,
    command: str,
    event_id: str,
    input_payload: dict[str, Any],
    output_payload: dict[str, Any],
    policy_status: ResearchPolicyStatus,
    explanation: str,
    repo_root: Path | None = None,
    audit_path: Path | None = None,
) -> dict[str, Any]:
    """Append market audit.
    
    Args:
        command: The command value supplied by the caller.
        event_id: The event id value supplied by the caller.
        input_payload: The input payload value supplied by the caller.
        output_payload: The output payload value supplied by the caller.
        policy_status: The policy status value supplied by the caller.
        explanation: The explanation value supplied by the caller.
        repo_root: Repository root used to resolve fixtures, reports, or local state.
        audit_path: Filesystem path used by the operation.
    
    Returns:
        The dict[str, Any] result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    row = {
        "schema_version": "market_events.audit.v1",
        "timestamp_utc": utc_now_iso(),
        "command": command,
        "event_id": event_id,
        "input_hash": canonical_json_hash(input_payload),
        "output_hash": canonical_json_hash(output_payload),
        "policy_status": policy_status.value,
        "explanation": explanation,
    }
    path = audit_path or default_audit_path(repo_root)
    append_jsonl(path, row)
    return row
