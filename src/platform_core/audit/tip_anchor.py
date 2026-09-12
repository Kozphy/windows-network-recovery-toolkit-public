"""Tip anchor file — external memory of the audit chain tip hash.

A tip anchor records the latest ``current_hash`` (and record count) outside the
JSONL body so a fully rewritten but internally consistent chain can be detected
when the tip is compared.

Honest limits:
  * Same-directory tip is defense-in-depth only.
  * Stronger custody requires tip on separate media, signed tip, or WORM storage.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.audit.paths import TIP_ANCHOR_SCHEMA, tip_path_for
from src.platform_core.governance.chain_of_custody import verify_chain


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_tip_anchor(
    *,
    tip_hash: str,
    record_count: int,
    audit_path: Path,
) -> dict[str, Any]:
    """Build tip anchor.

    Args:
        tip_hash: tip hash supplied by the caller.
        record_count: record count supplied by the caller.
        audit_path: audit path supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        May read or write local platform records depending on inputs.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return {
        "schema_version": TIP_ANCHOR_SCHEMA,
        "anchored_at_utc": _now(),
        "audit_path": str(audit_path),
        "tip_hash": tip_hash,
        "record_count": int(record_count),
        "limitations": [
            "Tip match proves consistency with a previously recorded chain tip — not observation truth.",
            "Same-host tip files are not WORM; relocate or sign tips for stronger custody.",
        ],
    }


def write_tip_anchor(
    *,
    tip_hash: str,
    record_count: int,
    audit_path: Path,
    tip_path: Path | None = None,
) -> tuple[bool, str | None, Path]:
    """Write tip anchor JSON. Soft-fail: returns ``(False, error, path)`` on OSError."""
    target = tip_path or tip_path_for(audit_path)
    payload = build_tip_anchor(
        tip_hash=tip_hash,
        record_count=record_count,
        audit_path=audit_path,
    )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return True, None, target
    except OSError as exc:
        return False, str(exc), target


def load_tip_anchor(tip_path: Path) -> dict[str, Any] | None:
    """Load tip anchor.

    Args:
        tip_path: tip path supplied by the caller.

    Returns:
        The computed `dict[str, Any] | None` value.

    Side effects:
        Reads data from the requested source.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    if not tip_path.is_file():
        return None
    try:
        data = json.loads(tip_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def read_audit_records(audit_path: Path) -> list[dict[str, Any]]:
    """Read audit records.

    Args:
        audit_path: audit path supplied by the caller.

    Returns:
        The computed `list[dict[str, Any]]` value.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    if not audit_path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def verify_audit_with_tip(
    audit_path: Path,
    *,
    tip_path: Path | None = None,
    require_tip: bool = False,
) -> dict[str, Any]:
    """Verify hash chain and optional tip anchor match.

    Returns a structured result suitable for CLI JSON. Does not prove observations.
    """
    records = read_audit_records(audit_path)
    chain_ok, chain_msg = verify_chain(records) if records else (True, "empty_chain")
    actual_tip = str(records[-1].get("current_hash") or "genesis") if records else "genesis"
    tip_file = tip_path or tip_path_for(audit_path)
    tip = load_tip_anchor(tip_file)

    tip_present = tip is not None
    tip_match: bool | None
    count_match: bool | None
    tip_msg: str
    if not tip_present:
        tip_match = None
        count_match = None
        tip_msg = "tip_anchor_missing"
    else:
        assert tip is not None  # narrowed for type checkers after tip_present check
        tip_match = str(tip.get("tip_hash") or "") == actual_tip
        count_match = int(tip.get("record_count") or -1) == len(records)
        if tip_match and count_match:
            tip_msg = "tip_match"
        elif not tip_match:
            tip_msg = "tip_hash_mismatch"
        else:
            tip_msg = "tip_record_count_mismatch"

    verified = bool(chain_ok)
    if require_tip:
        verified = verified and tip_present and bool(tip_match) and bool(count_match)
    elif tip_present:
        verified = verified and bool(tip_match) and bool(count_match)

    return {
        "schema_version": "audit_verify_with_tip.v1",
        "audit_path": str(audit_path),
        "tip_path": str(tip_file),
        "records": len(records),
        "chain_verified": bool(chain_ok),
        "chain_message": chain_msg,
        "actual_tip_hash": actual_tip,
        "tip_present": tip_present,
        "tip_match": tip_match,
        "tip_record_count_match": count_match,
        "tip_message": tip_msg,
        "verified": verified,
        "limitations": [
            "Chain verify proves append-only consistency of the JSONL — not truth of payloads.",
            "Tip match proves consistency with a previously written tip file — not WORM immutability.",
        ],
    }
