"""Canonical domain event append path (hash-chained + tip anchor)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from src.platform_core.audit.paths import default_canonical_path
from src.platform_core.audit.tip_anchor import write_tip_anchor
from src.platform_core.domain_events.envelope import build_envelope
from src.platform_core.governance.chain_of_custody import audit_hash_body, chain_hash
from src.platform_core.io.locked_jsonl import jsonl_file_lock

_LAST_HASH = "genesis"


def _read_chain_tip(path: Path) -> str:
    """Return the last record's ``current_hash``, or ``genesis`` for an empty stream.

    Raises:
        ValueError: if the stream exists but the final non-empty line is not a
            valid JSON object with ``current_hash`` (avoids silently forking a
            second chain after a corrupt tail).
    """
    if not path.is_file():
        return "genesis"
    lines = path.read_text(encoding="utf-8").splitlines()
    records = [line for line in lines if line.strip()]
    if not records:
        return "genesis"
    try:
        last = json.loads(records[-1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"corrupt chain tail in {path}: last line is not valid JSON") from exc
    if not isinstance(last, dict):
        raise ValueError(f"corrupt chain tail in {path}: last record is not an object")
    tip = str(last.get("current_hash") or "")
    if not tip:
        raise ValueError(f"corrupt chain tail in {path}: last record has no current_hash")
    return tip


def _count_records(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def append_domain_event(
    event_type: str,
    *,
    source: str,
    payload: dict[str, Any] | None = None,
    actor: str | None = None,
    correlation_id: str = "",
    tenant_id: str | None = None,
    decision_id: str = "",
    incident_id: str = "",
    action_type: str | None = None,
    path: Path | None = None,
    write_tip: bool = True,
) -> dict[str, Any]:
    """Append one ``wnrt.domain_event.v1`` row to the canonical custody stream.

    Integrity fields are flat (``previous_hash`` / ``current_hash``) so existing
    ``verify_chain`` continues to work. ``custody`` holds model metadata only.
    """
    global _LAST_HASH
    target = path or default_canonical_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    with jsonl_file_lock(target):
        prev_hash = _read_chain_tip(target)
        envelope = build_envelope(
            event_type=event_type,
            source=source,
            payload=payload,
            actor=actor,
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            event_id=str(uuid.uuid4()),
            decision_id=decision_id,
            incident_id=incident_id,
            action_type=action_type,
            previous_hash=prev_hash,
            current_hash="",
            signature_status="hash_chained",
        )
        hash_body = audit_hash_body(envelope)
        current_hash = chain_hash(prev_hash, hash_body)
        envelope["current_hash"] = current_hash
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope, ensure_ascii=False, sort_keys=False) + "\n")
        _LAST_HASH = current_hash
        if write_tip:
            write_tip_anchor(
                tip_hash=current_hash,
                record_count=_count_records(target),
                audit_path=target,
            )
    return envelope


def reset_domain_chain_for_tests() -> None:
    global _LAST_HASH
    _LAST_HASH = "genesis"
