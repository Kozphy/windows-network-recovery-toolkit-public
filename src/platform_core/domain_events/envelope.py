"""Domain event envelope schema (wnrt.domain_event.v1)."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

DOMAIN_EVENT_SCHEMA = "wnrt.domain_event.v1"
LEGACY_AUDIT_SCHEMA = "erp.audit.v1"
SUPPORTED_SCHEMA_VERSIONS = frozenset({DOMAIN_EVENT_SCHEMA, LEGACY_AUDIT_SCHEMA})

# Fields excluded from hash body (must stay aligned with chain_of_custody).
INTEGRITY_FIELDS = frozenset({"previous_hash", "current_hash", "signature_status"})

REQUIRED_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "event_type",
        "timestamp_utc",
        "source",
        "tenant_id",
        "correlation_id",
        "payload",
        "previous_hash",
        "current_hash",
        "signature_status",
        "custody",
    }
)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_tenant_id() -> str:
    """Deployment/tenant scope — local default; override with ``WNT_TENANT_ID``."""
    return (os.environ.get("WNT_TENANT_ID") or "local").strip() or "local"


def build_envelope(
    *,
    event_type: str,
    source: str,
    payload: dict[str, Any] | None = None,
    actor: str | None = None,
    correlation_id: str = "",
    tenant_id: str | None = None,
    event_id: str | None = None,
    timestamp_utc: str | None = None,
    decision_id: str = "",
    incident_id: str = "",
    action_type: str | None = None,
    previous_hash: str = "genesis",
    current_hash: str = "",
    signature_status: str = "hash_chained",
) -> dict[str, Any]:
    """Build a domain event dict (hashes may be filled by the writer)."""
    eid = event_id or str(uuid.uuid4())
    corr = str(correlation_id or "")
    envelope: dict[str, Any] = {
        "schema_version": DOMAIN_EVENT_SCHEMA,
        "event_id": eid,
        # Bridge for older AuditRecord consumers / erp.audit readers.
        "audit_id": eid,
        "event_type": str(event_type),
        "timestamp_utc": timestamp_utc or _now_iso(),
        "source": str(source),
        "tenant_id": tenant_id if tenant_id is not None else default_tenant_id(),
        "correlation_id": corr,
        "trace_id": corr,
        "actor": actor if actor is not None else source,
        "decision_id": str(decision_id or ""),
        "incident_id": str(incident_id or ""),
        "payload": dict(payload or {}),
        "custody": {
            "model": "hash_chain_tip_v1",
            "limitations": [
                "Hash chain proves append-only consistency of this JSONL — not truth of payloads.",
                "Tip match is defense-in-depth on the same host — not WORM immutability.",
            ],
        },
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "signature_status": signature_status,
    }
    if action_type:
        envelope["action_type"] = action_type
    return envelope


def validate_envelope(record: dict[str, Any]) -> tuple[bool, str]:
    """Validate a ``wnrt.domain_event.v1`` record (not legacy)."""
    if not isinstance(record, dict):
        return False, "not_an_object"
    schema = str(record.get("schema_version") or "")
    if schema != DOMAIN_EVENT_SCHEMA:
        if schema in SUPPORTED_SCHEMA_VERSIONS:
            return False, "legacy_schema_use_compat"
        if not schema:
            return False, "missing_schema_version"
        return False, f"unsupported_schema_version:{schema}"
    missing = sorted(REQUIRED_ENVELOPE_FIELDS - set(record.keys()))
    if missing:
        return False, f"missing_fields:{','.join(missing)}"
    if not isinstance(record.get("payload"), dict):
        return False, "payload_not_object"
    if not isinstance(record.get("custody"), dict):
        return False, "custody_not_object"
    if not str(record.get("event_id") or "").strip():
        return False, "empty_event_id"
    if not str(record.get("event_type") or "").strip():
        return False, "empty_event_type"
    if not str(record.get("source") or "").strip():
        return False, "empty_source"
    return True, "ok"
