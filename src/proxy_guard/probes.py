"""Resilient subprocess probes — retries, timeouts, partial failure notes."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ..core.models import ProxyRegistrySnapshot
from .config import ProbeRetrySettings
from .registry import read_proxy_registry


def snapshot_totally_unreadable(snap: ProxyRegistrySnapshot) -> bool:
    """True when every HKCU field failed to parse (likely subprocess outage)."""
    return (
        snap.proxy_enable is None
        and snap.proxy_server is None
        and snap.auto_config_url is None
        and snap.auto_detect is None
        and snap.proxy_override is None
    )


def read_proxy_registry_with_retries(
    *,
    run: Callable[..., Any],
    settings: ProbeRetrySettings,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[ProxyRegistrySnapshot, tuple[str, ...]]:
    """Read HKCU proxy snapshot with retries on total probe failure.

    Args:
        run: ``subprocess.run`` injector.
        settings: Timeout per query (passed to registry reader) and retry budget.
        sleep_fn: Sleep between attempts (tests may stub).

    Returns:
        Best snapshot and human/machine notes for audit (e.g. ``probe_retry_exhausted``).
    """
    notes: list[str] = []
    last: ProxyRegistrySnapshot | None = None
    attempts = max(1, int(settings.max_attempts))
    for i in range(attempts):
        last = read_proxy_registry(run=run, query_timeout=settings.timeout_seconds)
        if not snapshot_totally_unreadable(last):
            if i > 0:
                notes.append(f"probe_recovered_after_attempts:{i + 1}")
            return last, tuple(notes)
        notes.append(f"probe_attempt_all_none:{i + 1}")
        if i + 1 < attempts:
            sleep_fn(settings.backoff_seconds * (2**i))

    assert last is not None
    notes.append("probe_retry_exhausted_partial_failure_accepted")
    return last, tuple(notes)
