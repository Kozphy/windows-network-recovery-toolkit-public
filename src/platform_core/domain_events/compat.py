"""Legacy erp.audit.v1 compatibility helpers."""

from __future__ import annotations

from typing import Any

from src.platform_core.domain_events.envelope import DOMAIN_EVENT_SCHEMA, LEGACY_AUDIT_SCHEMA


def is_legacy_audit_record(record: dict[str, Any]) -> bool:
    return str(record.get("schema_version") or "") == LEGACY_AUDIT_SCHEMA


def legacy_record_as_envelope_view(record: dict[str, Any]) -> dict[str, Any]:
    """Project a legacy AuditRecord into a read-only envelope-shaped view.

    Does not mutate or re-hash the stored line — verification still uses the
    original record body for chain checks.
    """
    if not is_legacy_audit_record(record):
        return dict(record)
    audit_id = str(record.get("audit_id") or "")
    action = str(record.get("action_type") or "event_received")
    payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
    detail = payload.get("detail") if isinstance(payload.get("detail"), dict) else {}
    source = str(
        detail.get("subsystem") or payload.get("subsystem") or record.get("actor") or "legacy_audit"
    )
    event_type = str(payload.get("event") or f"legacy.{action}")
    return {
        "schema_version": DOMAIN_EVENT_SCHEMA,
        "event_id": audit_id,
        "audit_id": audit_id,
        "event_type": event_type,
        "timestamp_utc": str(record.get("timestamp_utc") or ""),
        "source": source,
        "tenant_id": "legacy",
        "correlation_id": str(record.get("trace_id") or ""),
        "actor": str(record.get("actor") or "platform"),
        "decision_id": str(record.get("decision_id") or ""),
        "incident_id": str(record.get("incident_id") or ""),
        "action_type": action,
        "payload": payload,
        "custody": {
            "model": "hash_chain_tip_v1",
            "migrated_view": True,
            "original_schema_version": LEGACY_AUDIT_SCHEMA,
            "limitations": [
                "View-only projection of erp.audit.v1 — stored bytes are unchanged.",
            ],
        },
        "previous_hash": str(record.get("previous_hash") or ""),
        "current_hash": str(record.get("current_hash") or ""),
        "signature_status": str(record.get("signature_status") or "hash_chained"),
        "_legacy_source_record": True,
    }
