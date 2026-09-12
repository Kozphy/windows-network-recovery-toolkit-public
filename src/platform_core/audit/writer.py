"""Hash-chained audit JSONL writer with optional tip anchor refresh.

Module responsibility:
    Appends tamper-evident audit records to a canonical ``canonical_custody.jsonl``
    file using SHA-256 hash chaining.  Each appended record links to the hash of
    the previous record (``previous_hash``), making log-file truncation or record
    deletion detectable.  Optionally refreshes a sibling tip-anchor file
    (``*.tip.json``) within the same file lock window.

System placement:
    Called by every CLI command, API route, and background agent that must produce
    a governance-traceable audit trail.  File locking (``jsonl_file_lock``)
    serialises concurrent writers across threads or processes accessing the same
    JSONL path.

Key invariants:
    - The module-level ``_LAST_HASH`` sentinel tracks the most recently written
      hash within a single process; it does not replace reading the on-disk chain
      tip for multi-process safety (``_read_chain_tip`` re-reads the file under
      the lock).
    - ``reset_chain_for_tests()`` is the only sanctioned mutation of ``_LAST_HASH``
      outside of ``append_audit``; it must not be called in production paths.
    - Records are append-only; no update or delete operation is provided.
    - ``AUDIT_SCHEMA_VERSION`` from ``src/platform_core/__init__.py`` stamps every
      record.

Side effects:
    - Appends one JSON line to the target JSONL file (file-locked).
    - Optionally writes or refreshes the sibling ``{stem}.tip.json`` tip-anchor
      file within the same lock window.
    - Creates the parent directory tree if it does not exist.

Failure modes:
    JSON decode errors while reading the chain tip fall back to ``"genesis"``
    rather than aborting the write, preserving append availability at the cost of
    chain continuity.  Callers requiring strict chain integrity must run
    ``audit verify`` after recovery.

Audit Notes:
    Each ``AuditRecord.current_hash`` is computed by
    ``chain_hash(prev_hash, audit_hash_body(record))``.  Verification tooling
    (``audit verify``) replays this computation against the on-disk chain; any
    divergence indicates tampering or a partial write.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core import AUDIT_SCHEMA_VERSION
from src.platform_core.audit.paths import default_canonical_path
from src.platform_core.audit.tip_anchor import write_tip_anchor
from src.platform_core.contracts import AuditActionType, AuditRecord
from src.platform_core.governance.chain_of_custody import audit_hash_body, chain_hash
from src.platform_core.io.locked_jsonl import jsonl_file_lock

_LAST_HASH = "genesis"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_chain_tip(path: Path) -> str:
    if not path.is_file():
        return "genesis"
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return "genesis"
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError:
        return "genesis"
    return str(last.get("current_hash") or "genesis")


def _count_records(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def append_audit(
    action_type: AuditActionType,
    *,
    trace_id: str = "",
    decision_id: str = "",
    incident_id: str = "",
    actor: str = "platform",
    payload: dict[str, Any] | None = None,
    path: Path | None = None,
    write_tip: bool = True,
) -> AuditRecord:
    """Append one hash-chained audit record to the canonical JSONL custody file.

    Acquires a file lock on *path*, reads the current chain tip, constructs an
    ``AuditRecord`` with ``previous_hash`` set to the prior tip, computes
    ``current_hash`` via ``chain_hash``, appends the JSON-serialised record, and
    optionally refreshes the sibling tip-anchor file — all within a single lock
    window.

    Args:
        action_type: Discriminated action type from ``AuditActionType``
            (e.g. ``CLASSIFY``, ``POLICY_DECISION``, ``REMEDIATION_PREVIEW``).
        trace_id: Correlates records for a single CLI invocation or API request.
        decision_id: Links to a ``Decision`` object produced by the decision engine.
        incident_id: Links to an incident or evidence bundle.
        actor: Human-readable originator label (default: ``"platform"``).
        payload: Arbitrary structured payload dict stored alongside the record.
        path: Override the default canonical JSONL path; defaults to
            ``default_canonical_path()``.
        write_tip: When ``True`` (default), refreshes the sibling
            ``{stem}.tip.json`` tip-anchor file within the same lock window.

    Returns:
        The fully populated ``AuditRecord`` with ``current_hash`` set.

    Side effects:
        Appends one JSON line to *path* and optionally writes the tip-anchor file.

    Audit Notes:
        Hash continuity depends on all writers using this function via
        ``jsonl_file_lock``.  Direct file appends outside this function break the
        verifiable chain.
    """
    global _LAST_HASH
    target = path or default_canonical_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    with jsonl_file_lock(target):
        prev_hash = _read_chain_tip(target)
        record = AuditRecord(
            audit_id=str(uuid.uuid4()),
            schema_version=AUDIT_SCHEMA_VERSION,
            timestamp_utc=_now_iso(),
            action_type=action_type,
            trace_id=trace_id,
            decision_id=decision_id,
            incident_id=incident_id,
            actor=actor,
            payload=payload or {},
            previous_hash=prev_hash,
            current_hash="",
            signature_status="hash_chained",
        )
        hash_body = audit_hash_body(record.model_dump())
        current_hash = chain_hash(prev_hash, hash_body)
        record = record.model_copy(update={"current_hash": current_hash})
        with target.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")
        _LAST_HASH = current_hash
        if write_tip:
            write_tip_anchor(
                tip_hash=current_hash,
                record_count=_count_records(target),
                audit_path=target,
            )
    return record


def reset_chain_for_tests() -> None:
    """Reset chain for tests.

    Returns:
        None.

    Side effects:
        Updates process-local or test-scoped state.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    global _LAST_HASH
    _LAST_HASH = "genesis"
