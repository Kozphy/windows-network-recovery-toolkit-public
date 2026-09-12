"""Classifier worker — calls existing deterministic pipeline only."""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from backend.db import get_engine, init_trisk_schema
from backend.db.models import ClassificationStatus, EvidenceEvent
from backend.db.repositories import (
    append_audit_chain_row,
    incident_exists_for_evidence,
    mark_evidence_status,
    quarantine_evidence,
    store_incident_bundle,
)
from src.platform_core.governance.human_review import REVIEW_CLASSES
from windows_network_toolkit.analytics_pipeline import run_endpoint_analytics_pipeline

_log = logging.getLogger(__name__)


def _fixture_from_evidence(row: EvidenceEvent) -> dict[str, Any]:
    raw = dict(row.raw_snapshot or {})
    if "proxy_state" not in raw and row.evidence_type == "proxy_state":
        return {"proxy_state": raw, "endpoint_id": row.endpoint_id}
    if "proxy_state" not in raw:
        return {"proxy_state": raw, "endpoint_id": row.endpoint_id}
    return raw


def _mirror_jsonl_audit(payload: dict[str, Any]) -> None:
    audit_dir = Path(os.getenv("PLATFORM_DATA_DIR", "./platform_data"))
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / "audit.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, separators=(",", ":")) + "\n")


def run_classification_job(event_id: str) -> dict[str, Any]:
    """Idempotent classification job for one evidence event."""
    from backend.tracing import span
    from backend.trisk_logging import log_trisk

    log_trisk("classification_job_started", event_id=event_id)
    init_trisk_schema()
    with span("worker.classify", event_id=event_id):
        result = _run_classification_job_inner(event_id)
    log_trisk("classification_job_finished", event_id=event_id, result=result)
    return result


def _run_classification_job_inner(event_id: str) -> dict[str, Any]:
    with Session(get_engine()) as session:
        row = session.exec(select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)).first()
        if not row:
            raise ValueError(f"evidence not found: {event_id}")

        if incident_exists_for_evidence(session, event_id):
            mark_evidence_status(session, event_id, ClassificationStatus.CLASSIFIED.value)
            session.commit()
            return {"event_id": event_id, "skipped": True, "reason": "incident_exists"}

        try:
            fixture = _fixture_from_evidence(row)
            payload = run_endpoint_analytics_pipeline(fixture=fixture)
        except Exception as exc:
            quarantine_evidence(session, event_id, f"Classification failed: {exc}")
            session.commit()
            _log.exception("job_lifecycle event=failed event_id=%s", event_id)
            raise

        incidents = payload.get("incidents") or []
        if not incidents:
            quarantine_evidence(session, event_id, "No incident produced from evidence")
            session.commit()
            return {"event_id": event_id, "quarantined": True}

        incident = incidents[0]
        controls = [c for c in (payload.get("control_tests") or []) if c.get("incident_id") == incident.get("incident_id")]
        if not controls:
            controls = payload.get("control_tests") or []

        policy = (payload.get("policy_decisions") or [{}])[0] if payload.get("policy_decisions") else {
            "action": "OBSERVE",
            "outcome": "PREVIEW_ONLY",
            "dry_run": True,
        }

        stored = store_incident_bundle(
            session,
            event_id=event_id,
            endpoint_id=row.endpoint_id,
            incident_payload=incident,
            control_tests=controls,
            policy=policy,
        )
        # Tenant scope follows the evidence record so async classification cannot
        # detach an incident from the organization that owns the endpoint.
        if row.tenant_id:
            stored.tenant_id = row.tenant_id
            session.add(stored)

        primary = stored.primary_classification
        status = (
            ClassificationStatus.REVIEW_REQUIRED.value
            if primary in REVIEW_CLASSES
            else ClassificationStatus.CLASSIFIED.value
        )
        mark_evidence_status(session, event_id, status)

        audit_payload = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "event_id": event_id,
            "incident_id": stored.incident_id,
            "tenant_id": row.tenant_id,
            "classification": {"primary_classification": primary},
            "dry_run": True,
            "limitations": list(stored.limitations or []),
        }
        append_audit_chain_row(session, audit_payload)
        _mirror_jsonl_audit(audit_payload)

        from src.platform_core.events import TriskEventType, emit_trisk_event

        inc_agg = f"incident:{stored.incident_id}"
        emit_trisk_event(
            TriskEventType.INCIDENT_DETECTED,
            aggregate_id=inc_agg,
            aggregate_type="incident",
            correlation_id=event_id,
            payload={
                "incident_id": stored.incident_id,
                "event_id": event_id,
                "tenant_id": row.tenant_id,
                "primary_classification": primary,
            },
            limitations=list(stored.limitations or [])[:3],
        )
        emit_trisk_event(
            TriskEventType.RISK_CLASSIFIED,
            aggregate_id=inc_agg,
            aggregate_type="incident",
            correlation_id=event_id,
            payload={
                "incident_id": stored.incident_id,
                "confidence": stored.confidence,
                "proof_tier": stored.proof_tier,
            },
            limitations=["Ordinal confidence — not calibrated probability."],
        )
        for ct in controls:
            emit_trisk_event(
                TriskEventType.CONTROL_TEST_COMPLETED,
                aggregate_id=inc_agg,
                aggregate_type="incident",
                correlation_id=event_id,
                payload={
                    "control_id": ct.get("control_id"),
                    "test_result": ct.get("test_result"),
                    "incident_id": stored.incident_id,
                },
            )

        session.commit()

        try:
            from backend.trisk_metrics import inc_classification, observe_classification_latency

            inc_classification(primary)
            observe_classification_latency(0.0)
        except Exception:
            pass

        _log.info("job_lifecycle event=succeeded event_id=%s incident_id=%s", event_id, stored.incident_id)
        return {"event_id": event_id, "incident_id": stored.incident_id, "status": status}
