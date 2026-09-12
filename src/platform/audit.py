"""Unified append-only audit log for Multi-Domain Decision Platform."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.time_utils import utc_now_iso
from src.platform.models import PolicyStatus
from src.platform.serialization import content_hash

DEFAULT_AUDIT_PATH = Path("logs/platform_decision_audit.jsonl")


class AuditRecord(BaseModel):
    """Represent audit record data used by the toolkit.
    
    Attributes:
        timestamp_utc: Field or variant describing timestamp utc evidence or state.
        domain: Field or variant describing domain evidence or state.
        event_id: Field or variant describing event id evidence or state.
        command: Field or variant describing command evidence or state.
        input_hash: Field or variant describing input hash evidence or state.
        output_hash: Field or variant describing output hash evidence or state.
        policy_status: Field or variant describing policy status evidence or state.
        explanation: Field or variant describing explanation evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    domain: str
    event_id: str
    command: str
    input_hash: str
    output_hash: str
    policy_status: PolicyStatus
    explanation: str = ""


def append_audit(record: AuditRecord, *, path: Path | None = None) -> AuditRecord:
    """Append audit.
    
    Args:
        record: Evidence or domain record being processed.
        path: Filesystem path used by the operation.
    
    Returns:
        The AuditRecord result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    target = path or DEFAULT_AUDIT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")))
        fh.write("\n")
    return record


def read_audit_tail(*, limit: int = 50, path: Path | None = None) -> list[AuditRecord]:
    """Read audit tail.
    
    Args:
        limit: The limit value supplied by the caller.
        path: Filesystem path used by the operation.
    
    Returns:
        The list[AuditRecord] result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    target = path or DEFAULT_AUDIT_PATH
    if not target.is_file():
        return []
    rows: list[AuditRecord] = []
    for line in target.read_text(encoding="utf-8").strip().splitlines()[-limit:]:
        if line.strip():
            rows.append(AuditRecord.model_validate(json.loads(line)))
    return rows


def audit_pipeline_step(
    *,
    domain: str,
    event_id: str,
    command: str,
    input_payload: Any,
    output_payload: Any,
    policy_status: PolicyStatus,
    explanation: str,
    timestamp_utc: str | None = None,
    path: Path | None = None,
) -> AuditRecord:
    """Audit pipeline step.
    
    Args:
        domain: The domain value supplied by the caller.
        event_id: The event id value supplied by the caller.
        command: The command value supplied by the caller.
        input_payload: The input payload value supplied by the caller.
        output_payload: The output payload value supplied by the caller.
        policy_status: The policy status value supplied by the caller.
        explanation: The explanation value supplied by the caller.
        timestamp_utc: The timestamp utc value supplied by the caller.
        path: Filesystem path used by the operation.
    
    Returns:
        The AuditRecord result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    return append_audit(
        AuditRecord(
            timestamp_utc=timestamp_utc or utc_now_iso(),
            domain=domain,
            event_id=event_id,
            command=command,
            input_hash=content_hash(input_payload),
            output_hash=content_hash(output_payload),
            policy_status=policy_status,
            explanation=explanation,
        ),
        path=path,
    )
