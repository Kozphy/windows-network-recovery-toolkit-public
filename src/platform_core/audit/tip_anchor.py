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
    """Return the current UTC timestamp in audit tip-anchor format.

    Returns:
        An ISO-8601 UTC timestamp ending in ``Z``.

    Side effects:
        None beyond reading the system clock.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_tip_anchor(
    *,
    tip_hash: str,
    record_count: int,
    audit_path: Path,
) -> dict[str, Any]:
    """Build the non-WORM tip-anchor payload for an audit chain.

    Args:
        tip_hash: Latest ``current_hash`` observed by the writer.
        record_count: Number of JSONL records represented by the tip.
        audit_path: Audit JSONL path recorded for later verification.

    Returns:
        A tip-anchor dictionary with schema version, timestamps, and explicit
        custody limitations.

    Side effects:
        None.
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
    """Write tip-anchor JSON beside an audit chain.

    Args:
        tip_hash: Latest ``current_hash`` to record.
        record_count: Number of audit records represented by the tip.
        audit_path: Audit JSONL path associated with the tip.
        tip_path: Optional explicit tip destination; defaults to the sibling tip.

    Returns:
        ``(True, None, path)`` on success, or ``(False, error, path)`` on
        filesystem failure. Soft-fails without raising ``OSError``.

    Side effects:
        Creates parent directories and overwrites the tip-anchor file when
        possible.
    """
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
    """Load a tip-anchor file for verification.

    Args:
        tip_path: Path to the tip-anchor JSON file.

    Returns:
        The decoded dictionary payload, or ``None`` when the file is missing
        or not a JSON object.

    Side effects:
        Reads one filesystem path.
    """
    if not tip_path.is_file():
        return None
    try:
        data = json.loads(tip_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def read_audit_records(audit_path: Path) -> list[dict[str, Any]]:
    """Read dictionary-shaped JSONL rows for investigative tip checks.

    Args:
        audit_path: Audit JSONL path.

    Returns:
        Object-shaped rows only. Malformed and non-object lines are skipped
        because authoritative verification uses a stricter reader.

    Side effects:
        Reads one filesystem path.
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


def _read_audit_records_for_verification(
    audit_path: Path,
) -> tuple[list[dict[str, Any]], bool]:
    """Read audit rows and report malformed non-empty JSONL lines.

    Args:
        audit_path: Audit JSONL path.

    Returns:
        A tuple of ``(records, malformed)``. Invalid UTF-8, undecodable JSON,
        and non-object rows set ``malformed`` to ``True``.

    Side effects:
        Reads one filesystem path.
    """
    if not audit_path.is_file():
        return [], False
    records: list[dict[str, Any]] = []
    malformed = False
    try:
        lines = audit_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return [], True
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            malformed = True
            continue
        if isinstance(row, dict):
            records.append(row)
        else:
            malformed = True
    return records, malformed


def verify_audit_with_tip(
    audit_path: Path,
    *,
    tip_path: Path | None = None,
    require_tip: bool = False,
) -> dict[str, Any]:
    """Verify hash-chain consistency and optional tip-anchor match.

    Args:
        audit_path: Audit JSONL path to verify.
        tip_path: Optional tip-anchor path; defaults to the sibling tip file.
        require_tip: When ``True``, missing or mismatched tips fail verification.

    Returns:
        A structured CLI-ready result describing chain status, tip presence,
        tip match, and explicit custody limitations. Does not prove that the
        recorded observations are true.

    Side effects:
        Reads the audit JSONL and tip-anchor files.
    """
    records, malformed = _read_audit_records_for_verification(audit_path)
    chain_ok, chain_msg = verify_chain(records) if records else (True, "empty_chain")
    if malformed:
        chain_ok, chain_msg = False, "malformed_audit_row"
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
