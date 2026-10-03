"""Optional continuous classification-outbox sweeper daemon.

Module responsibility:
    Periodically call the same sweep logic as the admin HTTP endpoint so pending
    outbox rows can drain without a human trigger.

System placement:
    Started/stopped from ``backend.main`` FastAPI lifespan via
    ``start_outbox_sweeper`` / ``stop_outbox_sweeper``. Status fields surface on
    ``GET /v1/classification-outbox/status`` through ``sweeper_runtime_snapshot``.

Key invariants:
    - Disabled by default (``TRISK_OUTBOX_SWEEPER_ENABLED`` unset/false) so pytest
      and local demos do not race queue dispatch.
    - Daemon thread is process-local; not a cluster leader claim.
    - First sweep waits one interval after start so API startup is not blocked.

Side effects:
    Background thread; DB sessions per tick; queue enqueue via product_outbox;
    in-process sweeper loop/error metrics; logging.

Failure modes:
    Tick exceptions are logged and counted; the loop keeps running. Invalid
    interval env falls back to 30s (clamped 1–3600).

Audit Notes:
    Daemon ticks do not append ``classification_outbox.swept`` audit rows; use the
    admin POST sweep endpoint when an auditable operator action is required.

Engineering Notes:
    Opt-in daemon avoids surprising local dispatch and test flakiness. A
    multi-instance leader-elected sweeper is intentionally out of scope here.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from sqlmodel import Session

from backend.product_outbox import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_SWEEP_LIMIT,
    sweep_pending_classification_outbox,
)
from backend.trisk_metrics import inc

logger = logging.getLogger(__name__)

SWEEPER_ENABLED_ENV = "TRISK_OUTBOX_SWEEPER_ENABLED"
SWEEPER_INTERVAL_ENV = "TRISK_OUTBOX_SWEEPER_INTERVAL_SECONDS"
METRIC_SWEEPER_LOOPS = "classification_outbox_sweeper_loops_total"
METRIC_SWEEPER_ERRORS = "classification_outbox_sweeper_errors_total"

_stop = threading.Event()
_thread: threading.Thread | None = None
_lock = threading.Lock()


def outbox_sweeper_enabled() -> bool:
    """Return whether the continuous sweeper daemon may start.

    Reads ``TRISK_OUTBOX_SWEEPER_ENABLED``. Default off when unset.

    Returns:
        True when env is one of ``1``, ``true``, ``yes``, ``on`` (case-insensitive).

    Side effects:
        None.
    """
    raw = (os.getenv(SWEEPER_ENABLED_ENV) or "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def outbox_sweeper_interval_seconds() -> float:
    """Return sweeper sleep interval in seconds.

    Reads ``TRISK_OUTBOX_SWEEPER_INTERVAL_SECONDS`` (default 30). Non-numeric
    values fall back to 30.0. Result is clamped to ``[1.0, 3600.0]``.

    Returns:
        Interval used between sweep ticks.

    Side effects:
        None.
    """
    raw = (os.getenv(SWEEPER_INTERVAL_ENV) or "30").strip()
    try:
        value = float(raw)
    except ValueError:
        return 30.0
    return max(1.0, min(value, 3600.0))


def run_sweeper_once(
    *,
    limit: int = DEFAULT_SWEEP_LIMIT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    force: bool = False,
) -> dict[str, Any]:
    """Run one sweep iteration on a fresh DB session.

    Safe for daemon ticks and unit tests. Ensures schema init before opening
    the session.

    Args:
        limit: Max pending rows to consider.
        max_attempts: Poison-message skip threshold.
        force: Override dispatch feature flag (usually false for daemon ticks).

    Returns:
        Same summary shape as ``sweep_pending_classification_outbox``.

    Side effects:
        May commit outbox updates and enqueue classification jobs.
    """
    from backend.db import get_engine, init_trisk_schema

    init_trisk_schema()
    with Session(get_engine()) as session:
        return sweep_pending_classification_outbox(
            session,
            limit=limit,
            max_attempts=max_attempts,
            force=force,
            respect_backoff=True,
        )


def _loop() -> None:
    """Daemon body: wait ``interval``, then sweep until stop is signaled."""
    interval = outbox_sweeper_interval_seconds()
    logger.info(
        "classification_outbox_sweeper started interval_seconds=%s",
        interval,
    )
    # Initial wait so API startup is not blocked by a first sweep.
    while not _stop.wait(interval):
        try:
            result = run_sweeper_once()
            inc(METRIC_SWEEPER_LOOPS)
            pending = result.get("pending_remaining")
            dispatched = result.get("dispatched")
            if dispatched or pending:
                logger.info(
                    "classification_outbox_sweeper tick dispatched=%s pending_remaining=%s",
                    dispatched,
                    pending,
                )
        except Exception:  # noqa: BLE001 — daemon must keep running
            inc(METRIC_SWEEPER_ERRORS)
            logger.exception("classification_outbox_sweeper tick failed")


def start_outbox_sweeper() -> bool:
    """Start the background sweeper thread when enabled.

    Idempotency:
        If a live thread already exists, returns True without starting another.

    Returns:
        True when a thread is running (started now or already alive); False when
        the feature flag disables the sweeper.

    Side effects:
        May spawn a daemon thread named ``classification-outbox-sweeper``.
    """
    global _thread
    if not outbox_sweeper_enabled():
        logger.info("classification_outbox_sweeper disabled (%s)", SWEEPER_ENABLED_ENV)
        return False
    with _lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(
            target=_loop,
            name="classification-outbox-sweeper",
            daemon=True,
        )
        _thread.start()
        return True


def stop_outbox_sweeper(*, join_timeout: float = 2.0) -> None:
    """Signal the sweeper thread to stop and join briefly.

    Idempotency:
        Safe to call when no thread is running.

    Args:
        join_timeout: Seconds to wait for the thread to exit after signaling stop.

    Side effects:
        Sets the stop event; may join the thread; clears the module thread ref.
    """
    global _thread
    with _lock:
        _stop.set()
        thread = _thread
        _thread = None
    if thread is not None and thread.is_alive():
        thread.join(timeout=join_timeout)


def sweeper_runtime_snapshot() -> dict[str, Any]:
    """Return process-local sweeper configuration and thread liveness.

    Returns:
        Dict with enabled flag, env name, interval, ``sweeper_thread_alive``, and
        ``limitations`` explaining opt-in and non-cluster semantics.

    Side effects:
        None.
    """
    alive = _thread is not None and _thread.is_alive()
    return {
        "sweeper_enabled": outbox_sweeper_enabled(),
        "sweeper_flag_env": SWEEPER_ENABLED_ENV,
        "sweeper_interval_seconds": outbox_sweeper_interval_seconds(),
        "sweeper_thread_alive": alive,
        "limitations": [
            "Daemon is opt-in; default off avoids test races and local surprise dispatch.",
            "Thread liveness is process-local observation, not a cluster leader claim.",
        ],
    }
