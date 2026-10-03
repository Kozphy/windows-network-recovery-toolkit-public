"""Verify canonical domain event streams (envelope + chain + tip)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.platform_core.audit.paths import tip_path_for
from src.platform_core.audit.tip_anchor import load_tip_anchor
from src.platform_core.domain_events.compat import is_legacy_audit_record
from src.platform_core.domain_events.envelope import (
    DOMAIN_EVENT_SCHEMA,
    LEGACY_AUDIT_SCHEMA,
    SUPPORTED_SCHEMA_VERSIONS,
    validate_envelope,
)
from src.platform_core.governance.chain_of_custody import verify_chain


def read_domain_records(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(parsed_records, malformed_lines)``.

    Malformed entries are reported separately; they are not included in chain verify.
    """
    if not path.is_file():
        return [], []
    records: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        raw = line.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            malformed.append(
                {"index": idx, "error": f"json_decode:{exc}", "line_preview": raw[:120]}
            )
            continue
        if not isinstance(row, dict):
            malformed.append({"index": idx, "error": "not_an_object", "line_preview": raw[:120]})
            continue
        records.append(row)
    return records, malformed


def verify_domain_stream(
    path: Path,
    *,
    tip_path: Path | None = None,
    require_tip: bool = False,
    require_domain_schema: bool = False,
) -> dict[str, Any]:
    """Verify hash chain, envelope/legacy schemas, and optional tip anchor.

    This is the single verification API for the domain event kernel.
    CLI: ``python -m windows_network_toolkit audit verify <path> --check-tip``.
    """
    records, malformed = read_domain_records(path)
    envelope_errors: list[dict[str, Any]] = []
    legacy_count = 0
    domain_count = 0
    unsupported: list[dict[str, Any]] = []

    for idx, rec in enumerate(records):
        schema = str(rec.get("schema_version") or "")
        if schema == DOMAIN_EVENT_SCHEMA:
            domain_count += 1
            ok, msg = validate_envelope(rec)
            if not ok:
                envelope_errors.append({"index": idx, "error": msg})
        elif schema == LEGACY_AUDIT_SCHEMA:
            legacy_count += 1
            if require_domain_schema:
                envelope_errors.append({"index": idx, "error": "legacy_not_allowed"})
            elif (
                not rec.get("audit_id")
                or not rec.get("action_type")
                or not rec.get("timestamp_utc")
            ):
                envelope_errors.append({"index": idx, "error": "legacy_missing_required"})
        elif schema in SUPPORTED_SCHEMA_VERSIONS:
            # Future: already covered
            pass
        else:
            unsupported.append(
                {
                    "index": idx,
                    "schema_version": schema or None,
                    "error": "unsupported_schema_version",
                }
            )

    # Chain verify only when no malformed lines interrupt the logical stream.
    # Malformed lines are integrity failures even if skipped for hashing.
    chain_ok, chain_msg = (True, "empty_chain") if not records else verify_chain(records)
    if malformed:
        chain_ok = False
        chain_msg = f"malformed_records:{len(malformed)}"

    actual_tip = str(records[-1].get("current_hash") or "genesis") if records else "genesis"
    tip_file = tip_path or tip_path_for(path)
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
        tip_match = str(tip.get("tip_hash") or "") == actual_tip
        # Tip count should match parseable records (malformed lines are not chained).
        count_match = int(tip.get("record_count") or -1) == len(records)
        if tip_match and count_match:
            tip_msg = "tip_match"
        elif not tip_match:
            tip_msg = "tip_hash_mismatch"
        else:
            tip_msg = "tip_record_count_mismatch"

    schema_ok = not envelope_errors and not unsupported
    verified = bool(chain_ok) and schema_ok
    if require_tip:
        verified = verified and tip_present and bool(tip_match) and bool(count_match)
    elif tip_present:
        verified = verified and bool(tip_match) and bool(count_match)

    return {
        "schema_version": "domain_stream_verify.v1",
        "audit_path": str(path),
        "tip_path": str(tip_file),
        "records": len(records),
        "domain_event_records": domain_count,
        "legacy_audit_records": legacy_count,
        "malformed_records": malformed,
        "envelope_errors": envelope_errors,
        "unsupported_schema": unsupported,
        "chain_verified": bool(chain_ok),
        "chain_message": chain_msg,
        "actual_tip_hash": actual_tip,
        "tip_present": tip_present,
        "tip_match": tip_match,
        "tip_record_count_match": count_match,
        "tip_message": tip_msg,
        "verified": verified,
        "limitations": [
            "Verification proves stream integrity and envelope shape — not truth of observations.",
            "Legacy erp.audit.v1 rows are accepted unless require_domain_schema=True.",
            "Tip match is not WORM immutability.",
        ],
    }


def inspect_stream(path: Path, *, limit: int = 20) -> dict[str, Any]:
    """Return a compact inspection summary for demos/README."""
    records, malformed = read_domain_records(path)
    sample: list[dict[str, Any]] = []
    for rec in records[-limit:]:
        sample.append(
            {
                "schema_version": rec.get("schema_version"),
                "event_id": rec.get("event_id") or rec.get("audit_id"),
                "event_type": rec.get("event_type")
                or (rec.get("payload") or {}).get("event")
                or rec.get("action_type"),
                "source": rec.get("source") or rec.get("actor"),
                "timestamp_utc": rec.get("timestamp_utc"),
                "is_legacy": is_legacy_audit_record(rec),
                "current_hash": str(rec.get("current_hash") or "")[:16],
            }
        )
    return {
        "schema_version": "domain_stream_inspect.v1",
        "path": str(path),
        "record_count": len(records),
        "malformed_count": len(malformed),
        "sample": sample,
    }
