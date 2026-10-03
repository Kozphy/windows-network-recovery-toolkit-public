"""Canonical audit JSONL schema."""

from __future__ import annotations

import json
from typing import Any

from src.platform_core import AUDIT_SCHEMA_VERSION
from src.platform_core.contracts import AuditActionType

AUDIT_ACTIONS: tuple[AuditActionType, ...] = (
    "event_received",
    "evidence_attached",
    "hypothesis_created",
    "decision_created",
    "policy_evaluated",
    "remediation_previewed",
    "human_approval_requested",
    "human_approval_granted",
    "action_executed",
    "validation_completed",
    "rollback_completed",
    "outcome_recorded",
    "replay_certified",
    "stakeholder_resolved",
    "timing_evaluated",
    "coordination_status_set",
    "decision_context_built",
)


def audit_json_schema() -> dict[str, Any]:
    """Build the JSON Schema exposed to exporters and audit tooling.

    Returns:
        A new dictionary describing required fields, supported action types,
        schema version, and hash/signature fields. The returned object may be
        modified by the caller without changing module state.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ERPAuditRecord",
        "type": "object",
        "required": ["audit_id", "schema_version", "timestamp_utc", "action_type"],
        "properties": {
            "audit_id": {"type": "string"},
            "schema_version": {"const": AUDIT_SCHEMA_VERSION},
            "timestamp_utc": {"type": "string"},
            "action_type": {"enum": list(AUDIT_ACTIONS)},
            "trace_id": {"type": "string"},
            "decision_id": {"type": "string"},
            "incident_id": {"type": "string"},
            "actor": {"type": "string"},
            "payload": {"type": "object"},
            "previous_hash": {"type": "string"},
            "current_hash": {"type": "string"},
            "signature_status": {"enum": ["unsigned", "hash_chained", "signed"]},
        },
    }


def validate_audit_record(record: dict[str, Any]) -> bool:
    """Perform the reader's minimum structural validation.

    Args:
        record: Decoded JSON object from an audit JSONL line.

    Returns:
        ``True`` when the required identity, timestamp, schema, and action
        fields are present. This is not cryptographic chain verification.
    """
    required = {"audit_id", "schema_version", "timestamp_utc", "action_type"}
    return required.issubset(record.keys())


def export_schema_json() -> str:
    """Serialize :func:`audit_json_schema` as indented JSON.

    Returns:
        Pretty-printed JSON Schema text for exporters and documentation.

    Side effects:
        None.
    """
    return json.dumps(audit_json_schema(), indent=2)
