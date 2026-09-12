"""Optional PostgreSQL persistence — JSONL remains default local-first store."""

from __future__ import annotations

import json
import os

from platform_core.reliability.models import NormalizedPlatformEvent, PlatformDecisionRecord


def database_url() -> str | None:
    """Provide database url behavior for toolkit workflows.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return os.environ.get("PLATFORM_DATABASE_URL") or os.environ.get("DATABASE_URL")


def is_postgres_configured() -> bool:
    """Evaluate the is postgres configured condition.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    url = database_url()
    return bool(url and url.startswith("postgres"))


def append_event_pg(event: NormalizedPlatformEvent) -> bool:
    """Append event to PostgreSQL when configured; return False if skipped."""
    url = database_url()
    if not url:
        return False
    try:
        import psycopg2  # type: ignore[import-untyped]
    except ImportError:
        return False
    conn = psycopg2.connect(url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO platform_events
                (event_id, timestamp_utc, endpoint_id, source_kind, signal_name, evidence_tier, payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    event.event_id,
                    event.timestamp_utc,
                    event.endpoint_id,
                    event.source_kind,
                    event.signal_name,
                    event.evidence_tier,
                    json.dumps(event.payload),
                ),
            )
        conn.commit()
        return True
    finally:
        conn.close()


def append_decision_pg(record: PlatformDecisionRecord) -> bool:
    """Append decision pg for toolkit workflows.

    Args:
        record: Value supplied by the caller for record.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    url = database_url()
    if not url:
        return False
    try:
        import psycopg2  # type: ignore[import-untyped]
    except ImportError:
        return False
    conn = psycopg2.connect(url)
    try:
        record.model_dump(mode="json")
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO platform_decisions
                (decision_id, run_id, timestamp_utc, endpoint_id, state_path,
                 accepted_hypothesis, policy_outcome, policy_reason_codes,
                 evidence_graph_summary, hypothesis_ranking, event_ids, limitations,
                 audit_signature, schema_version)
                VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,%s,%s)
                ON CONFLICT (decision_id) DO NOTHING
                """,
                (
                    record.decision_id,
                    record.run_id,
                    record.timestamp_utc,
                    record.endpoint_id,
                    json.dumps(record.state_path),
                    record.accepted_hypothesis,
                    record.policy_outcome,
                    json.dumps(record.policy_reason_codes),
                    json.dumps(record.evidence_graph_summary),
                    json.dumps(record.hypothesis_ranking),
                    json.dumps(record.event_ids),
                    json.dumps(record.limitations),
                    record.audit_signature,
                    record.schema_version,
                ),
            )
        conn.commit()
        return True
    finally:
        conn.close()
