"""Classification outbox dispatch, feature flag, operator sweep, and metrics.

Module responsibility:
    Durable handoff from committed evidence rows to classification queue enqueue.
    Evidence commit and outbox row creation stay transactional in the ingest path;
    queue enqueue happens after commit (or via sweeper retry).

System placement:
    Called from ``backend.product_v1_routes`` after agent evidence ingest, from
    admin ``GET/POST /v1/classification-outbox/*``, and from
    ``backend.product_outbox_sweeper`` when the optional daemon is enabled.

Key invariants:
    - Failed or skipped dispatch leaves the outbox row ``pending`` so operators
      can re-drive without re-posting evidence.
    - Already-``dispatched`` rows with a ``job_id`` are not re-enqueued.
    - Timestamps use UTC (``datetime.now(UTC)``); naive DB values are treated as UTC
      when computing ages.

Side effects:
    SQL commits on outbox (and optionally EvidenceEvent.job_id); in-process
    Prometheus counters/gauges via ``backend.trisk_metrics``; queue
    ``enqueue_classification_job`` when dispatch runs.

Failure modes:
    Missing outbox row → ``(None, "pending")``. Queue exceptions → row stays
    pending with truncated ``last_error``. Dispatch flag off → skipped metric,
    no enqueue unless ``force=True``.

Audit Notes:
    Dispatch success is not classification success. Prefer status/metrics over
    re-ingest when recovering backlog. See docs/runbooks/classification-outbox-stuck.md.

Engineering Notes:
    Transactional outbox + post-commit enqueue avoids workers seeing unpublished
    event_ids. In-process metrics reset on process restart (not multi-instance
    authoritative).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, col, func, select

from backend.product_v1_models import ClassificationOutbox
from backend.trisk_metrics import inc, set_gauge

OUTBOX_DISPATCH_ENV = "TRISK_OUTBOX_DISPATCH_ENABLED"
DEFAULT_SWEEP_LIMIT = 50
DEFAULT_MAX_ATTEMPTS = 20
DEFAULT_RETRY_BASE_SECONDS = 5.0
DEFAULT_RETRY_MAX_SECONDS = 300.0
OUTBOX_RETRY_BASE_ENV = "TRISK_OUTBOX_RETRY_BASE_SECONDS"
OUTBOX_RETRY_MAX_ENV = "TRISK_OUTBOX_RETRY_MAX_SECONDS"

METRIC_PENDING = "classification_outbox_pending"
METRIC_DISPATCH_ATTEMPTS = "classification_outbox_dispatch_attempts_total"
METRIC_DISPATCH_SUCCESS = "classification_outbox_dispatch_success_total"
METRIC_DISPATCH_FAILURES = "classification_outbox_dispatch_failures_total"
METRIC_DISPATCH_SKIPPED = "classification_outbox_dispatch_skipped_total"
METRIC_SWEEP_RUNS = "classification_outbox_sweep_runs_total"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _bounded_env_seconds(name: str, default: float) -> float:
    """Read a positive retry interval and clamp it to one hour."""
    raw = (os.getenv(name) or str(default)).strip()
    try:
        value = float(raw)
    except ValueError:
        return default
    return max(0.1, min(value, 3600.0))


def retry_backoff_seconds(attempts: int) -> float:
    """Return capped exponential delay after a failed dispatch attempt."""
    if attempts <= 0:
        return 0.0
    base = _bounded_env_seconds(OUTBOX_RETRY_BASE_ENV, DEFAULT_RETRY_BASE_SECONDS)
    maximum = _bounded_env_seconds(OUTBOX_RETRY_MAX_ENV, DEFAULT_RETRY_MAX_SECONDS)
    maximum = max(base, maximum)
    return min(base * (2 ** min(attempts - 1, 30)), maximum)


def outbox_retry_due(row: ClassificationOutbox, *, now: datetime | None = None) -> bool:
    """Return whether a pending row has waited through its retry backoff."""
    if row.attempts <= 0:
        return True
    updated = row.updated_at
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=UTC)
    current = now or _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current >= updated + timedelta(seconds=retry_backoff_seconds(row.attempts))


def outbox_dispatch_enabled() -> bool:
    """Return whether queue dispatch is allowed.

    Reads ``TRISK_OUTBOX_DISPATCH_ENABLED``. Missing or empty env defaults to on
    so existing deployments keep enqueueing after evidence commit.

    Returns:
        True when the flag is one of ``1``, ``true``, ``yes``, ``on`` (case-insensitive).

    Side effects:
        None (env read only).
    """
    raw = (os.getenv(OUTBOX_DISPATCH_ENV) or "true").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def count_pending_outbox(session: Session) -> int:
    """Count ClassificationOutbox rows with status ``pending``.

    Args:
        session: Open SQLModel session bound to the technology-risk engine.

    Returns:
        Non-negative integer count (0 when none).

    Side effects:
        None (read-only query).
    """
    result = session.exec(
        select(func.count())
        .select_from(ClassificationOutbox)
        .where(ClassificationOutbox.status == "pending")
    ).one()
    return int(result or 0)


def refresh_pending_gauge(session: Session) -> int:
    """Recount pending outbox rows and publish the in-process gauge.

    Args:
        session: Open SQLModel session.

    Returns:
        Current pending count after refresh.

    Side effects:
        Updates ``classification_outbox_pending`` via ``set_gauge``.
    """
    pending = count_pending_outbox(session)
    set_gauge(METRIC_PENDING, float(pending))
    return pending


def dispatch_classification_outbox(
    session: Session,
    *,
    event_id: str,
    force: bool = False,
) -> tuple[str | None, str]:
    """Enqueue classification for a pending outbox row after evidence is committed.

    Idempotency:
        If the row is already ``dispatched`` with a ``job_id``, returns that job
        without a second enqueue. Missing rows return ``(None, "pending")``.

    Args:
        session: Open session; this function commits on skip/fail/success paths.
        event_id: Evidence / outbox event identifier.
        force: When True, enqueue even if ``TRISK_OUTBOX_DISPATCH_ENABLED`` is off
            (operator recovery drills).

    Returns:
        ``(job_id, classification_status)``. ``job_id`` is None when dispatch did
        not enqueue; ``classification_status`` comes from EvidenceEvent when present,
        otherwise ``"pending"``.

    Side effects:
        May commit ClassificationOutbox and EvidenceEvent.job_id; increments
        attempt/success/failure/skipped metrics; calls queue backend enqueue.

    Audit Notes:
        Queue failures leave the row pending with ``last_error`` (truncated to 512
        chars) so evidence remains durable. Detect via status endpoint / metrics;
        recover with sweep or flag re-enable — do not require re-POST of evidence.
    """
    from backend.db.models import EvidenceEvent
    from backend.queue import get_queue_backend

    outbox = session.exec(
        select(ClassificationOutbox).where(ClassificationOutbox.event_id == event_id)
    ).first()
    if outbox is None:
        refresh_pending_gauge(session)
        return None, "pending"
    if outbox.status == "dispatched" and outbox.job_id:
        evidence = session.exec(
            select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)
        ).first()
        refresh_pending_gauge(session)
        return outbox.job_id, (evidence.classification_status if evidence else "pending")

    if not force and not outbox_dispatch_enabled():
        outbox.status = "pending"
        outbox.last_error = f"dispatch disabled via {OUTBOX_DISPATCH_ENV}"
        outbox.updated_at = _utc_now()
        session.add(outbox)
        session.commit()
        inc(METRIC_DISPATCH_SKIPPED)
        refresh_pending_gauge(session)
        return None, "pending"

    outbox.attempts += 1
    outbox.updated_at = _utc_now()
    inc(METRIC_DISPATCH_ATTEMPTS)
    try:
        job = get_queue_backend().enqueue_classification_job(
            event_id=outbox.event_id,
            idempotency_key=outbox.idempotency_key,
        )
    except Exception as exc:  # noqa: BLE001 — keep evidence durable; surface deferred status
        outbox.status = "pending"
        outbox.last_error = str(exc)[:512]
        session.add(outbox)
        session.commit()
        inc(METRIC_DISPATCH_FAILURES)
        refresh_pending_gauge(session)
        return None, "pending"

    outbox.status = "dispatched"
    outbox.job_id = job.job_id
    outbox.last_error = None
    outbox.dispatched_at = _utc_now()
    session.add(outbox)
    evidence = session.exec(select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)).first()
    if evidence is not None:
        evidence.job_id = job.job_id
        session.add(evidence)
    session.commit()
    inc(METRIC_DISPATCH_SUCCESS)
    refresh_pending_gauge(session)
    return job.job_id, evidence.classification_status if evidence else "pending"


def outbox_status_snapshot(session: Session) -> dict[str, Any]:
    """Build an operator-facing pending/dispatch readiness snapshot.

    Not an SLO attestation or queue-health proof. Includes optional sweeper
    runtime fields when the sweeper module imports cleanly.

    Args:
        session: Open SQLModel session.

    Returns:
        Dict with ``dispatch_enabled``, ``pending_count``, oldest pending age
        (UTC-based seconds), high-attempt count, ``limitations``, and sweeper
        fields when available.

    Side effects:
        Refreshes the pending gauge (read + set_gauge).
    """
    pending = refresh_pending_gauge(session)
    oldest = session.exec(
        select(ClassificationOutbox)
        .where(ClassificationOutbox.status == "pending")
        .order_by(col(ClassificationOutbox.created_at).asc())
        .limit(1)
    ).first()
    oldest_age_seconds: float | None = None
    oldest_event_id: str | None = None
    if oldest is not None:
        created = oldest.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        oldest_age_seconds = max(0.0, (_utc_now() - created).total_seconds())
        oldest_event_id = oldest.event_id

    high_attempt = session.exec(
        select(func.count())
        .select_from(ClassificationOutbox)
        .where(
            ClassificationOutbox.status == "pending",
            ClassificationOutbox.attempts >= DEFAULT_MAX_ATTEMPTS,
        )
    ).one()

    return {
        "dispatch_enabled": outbox_dispatch_enabled(),
        "dispatch_flag_env": OUTBOX_DISPATCH_ENV,
        "pending_count": pending,
        "oldest_pending_event_id": oldest_event_id,
        "oldest_pending_age_seconds": oldest_age_seconds,
        "pending_at_or_above_max_attempts": int(high_attempt or 0),
        "max_attempts_default": DEFAULT_MAX_ATTEMPTS,
        "limitations": [
            "Pending count is observation of durable handoff rows, not proof of queue health.",
            "Metrics are in-process until scraped; they reset on process restart.",
        ],
        **_sweeper_fields(),
    }


def _sweeper_fields() -> dict[str, Any]:
    """Attach sweeper snapshot fields; degrade to disabled flags on import/runtime errors."""
    try:
        from backend.product_outbox_sweeper import sweeper_runtime_snapshot

        snap = sweeper_runtime_snapshot()
        return {
            "sweeper_enabled": snap["sweeper_enabled"],
            "sweeper_flag_env": snap["sweeper_flag_env"],
            "sweeper_interval_seconds": snap["sweeper_interval_seconds"],
            "sweeper_thread_alive": snap["sweeper_thread_alive"],
        }
    except Exception:  # noqa: BLE001 — status must still return core outbox fields
        return {
            "sweeper_enabled": False,
            "sweeper_thread_alive": False,
        }


def sweep_pending_classification_outbox(
    session: Session,
    *,
    limit: int = DEFAULT_SWEEP_LIMIT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    force: bool = False,
    respect_backoff: bool = False,
) -> dict[str, Any]:
    """Retry pending outbox rows up to ``limit`` (oldest first).

    Rows with ``attempts >= max_attempts`` are skipped so poison messages do not
    spin forever; operators must inspect ``last_error`` and fix the queue or reset.

    Args:
        session: Open session passed through to ``dispatch_classification_outbox``.
        limit: Max rows to consider this pass (clamped 1–500).
        max_attempts: Skip pending rows at or above this attempt count.
        force: Forwarded to dispatch to override the dispatch feature flag.
        respect_backoff: Defer recently failed rows until their capped exponential
            retry delay elapses. The daemon enables this; explicit admin sweeps do
            not, so operators can recover immediately after repairing the queue.

    Returns:
        Summary dict: ``swept``, ``dispatched``, ``failed``, ``deferred_backoff``,
        ``skipped_max_attempts``, ``pending_remaining``, per-row ``items``, and
        ``limitations``.

    Side effects:
        Increments sweep-run metric; may enqueue jobs and commit outbox rows.
        When dispatch is disabled and ``force`` is false, returns without enqueue.

    Idempotency:
        Already-dispatched rows are not selected (status filter is ``pending`` only).
        Re-running sweep on remaining pending rows is safe.

    Audit Notes:
        Manual API sweep also appends ``classification_outbox.swept`` via the route
        layer. Continuous daemon ticks do not write that audit event unless an
        admin calls the HTTP sweep endpoint.
    """
    lim = max(1, min(int(limit), 500))
    cap = max(1, int(max_attempts))
    inc(METRIC_SWEEP_RUNS)

    if not force and not outbox_dispatch_enabled():
        pending = refresh_pending_gauge(session)
        return {
            "dispatch_enabled": False,
            "swept": 0,
            "dispatched": 0,
            "failed": 0,
            "deferred_backoff": 0,
            "skipped_max_attempts": 0,
            "pending_remaining": pending,
            "items": [],
            "limitations": [
                f"Sweep skipped because {OUTBOX_DISPATCH_ENV} is disabled; pass force=true to override.",
            ],
        }

    rows = list(
        session.exec(
            select(ClassificationOutbox)
            .where(ClassificationOutbox.status == "pending")
            .order_by(col(ClassificationOutbox.created_at).asc())
            .limit(lim)
        )
    )

    items: list[dict[str, Any]] = []
    dispatched = 0
    failed = 0
    deferred_backoff = 0
    skipped_max = 0
    now = _utc_now()

    for row in rows:
        if row.attempts >= cap:
            skipped_max += 1
            items.append(
                {
                    "event_id": row.event_id,
                    "result": "skipped_max_attempts",
                    "attempts": row.attempts,
                    "last_error": row.last_error,
                }
            )
            continue
        if respect_backoff and not outbox_retry_due(row, now=now):
            deferred_backoff += 1
            items.append(
                {
                    "event_id": row.event_id,
                    "result": "deferred_backoff",
                    "attempts": row.attempts,
                    "retry_after_seconds": retry_backoff_seconds(row.attempts),
                }
            )
            continue
        job_id, classification_status = dispatch_classification_outbox(
            session, event_id=row.event_id, force=force
        )
        if job_id:
            dispatched += 1
            items.append(
                {
                    "event_id": row.event_id,
                    "result": "dispatched",
                    "job_id": job_id,
                    "classification_status": classification_status,
                }
            )
        else:
            failed += 1
            refreshed = session.exec(
                select(ClassificationOutbox).where(ClassificationOutbox.event_id == row.event_id)
            ).first()
            items.append(
                {
                    "event_id": row.event_id,
                    "result": "pending",
                    "attempts": refreshed.attempts if refreshed else None,
                    "last_error": refreshed.last_error if refreshed else None,
                }
            )

    pending_remaining = refresh_pending_gauge(session)
    return {
        "dispatch_enabled": outbox_dispatch_enabled() or force,
        "swept": len(rows),
        "dispatched": dispatched,
        "failed": failed,
        "deferred_backoff": deferred_backoff,
        "skipped_max_attempts": skipped_max,
        "pending_remaining": pending_remaining,
        "items": items,
        "limitations": [
            "Automatic retries are process-local and require the sweeper feature flag.",
            "Classification success is separate from outbox dispatch success.",
        ],
    }
