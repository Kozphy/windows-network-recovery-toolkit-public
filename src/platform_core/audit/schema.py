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
    """Return audit json schema.

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
    """Validate audit record.

    Args:
        record: record supplied by the caller.

    Returns:
        The computed `bool` value.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    required = {"audit_id", "schema_version", "timestamp_utc", "action_type"}
    return required.issubset(record.keys())


def export_schema_json() -> str:
    """Return export schema json.

    Returns:
        The computed `str` value.

    Side effects:
        May read or write local platform records depending on inputs.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return json.dumps(audit_json_schema(), indent=2)
