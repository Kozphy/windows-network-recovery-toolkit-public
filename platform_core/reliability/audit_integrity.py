"""Signed audit entries and tamper detection for platform decisions."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from platform_core.settings import get_settings

from .models import PlatformDecisionRecord


def _canonical_payload(record: PlatformDecisionRecord) -> str:
    blob = record.model_dump(mode="json")
    blob.pop("audit_signature", None)
    return json.dumps(blob, sort_keys=True, separators=(",", ":"))


def sign_decision_record(
    record: PlatformDecisionRecord,
    *,
    secret: str | None = None,
) -> PlatformDecisionRecord:
    """Attach HMAC-SHA256 signature for tamper detection."""
    key = secret or get_settings().resolved_api_key() or "local-dev-signing-key"
    digest = hmac.new(
        key.encode("utf-8"),
        _canonical_payload(record).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return record.model_copy(update={"audit_signature": digest})


def verify_decision_record(
    record: PlatformDecisionRecord,
    *,
    secret: str | None = None,
) -> tuple[bool, str]:
    """Verify signature; return (valid, reason)."""
    if not record.audit_signature:
        return False, "missing_signature"
    key = secret or get_settings().resolved_api_key() or "local-dev-signing-key"
    expected = hmac.new(
        key.encode("utf-8"),
        _canonical_payload(record).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if hmac.compare_digest(expected, record.audit_signature):
        return True, "ok"
    return False, "signature_mismatch"


def detect_tamper_in_jsonl(rows: list[dict[str, Any]], *, secret: str | None = None) -> list[dict[str, Any]]:
    """Return rows that fail signature verification."""
    bad: list[dict[str, Any]] = []
    for row in rows:
        try:
            rec = PlatformDecisionRecord(**row)
        except Exception:
            bad.append({"row": row, "reason": "schema_invalid"})
            continue
        ok, reason = verify_decision_record(rec, secret=secret)
        if not ok:
            bad.append({"run_id": rec.run_id, "reason": reason})
    return bad
