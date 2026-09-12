"""Background HKCU proxy watcher — emit events only on state change; no remediation.

Module responsibility:
    Poll WinINET proxy state on an interval, correlate a localhost listener when applicable,
    invoke the existing classification / proof-tier engines, and append ``EvidenceEvent``
    rows only when the comparable proxy identity tuple changes.

System placement:
    Owned by the monitoring dashboard runtime; also usable from tests via ``poll_once``.

Key invariants:
    * Never writes registry, kills processes, or remediates.
    * Soft-fails classification: falls back to coarse codes + limitations on exception.
    * First successful poll emits a baseline event; later polls emit only on change.

Side effects:
    * Appends to ``EvidenceEventStore`` (memory + optional JSONL).
    * Spawns a daemon thread named ``wnt-proxy-watcher``.

Idempotency:
    * ``start`` is a no-op when the thread is already alive.
    * Repeated polls with unchanged state return ``None`` (no duplicate events).

Audit Notes:
    * Misclassification is possible when engines raise — check event ``limitations``.
    * Listener PID is correlation with ProxyServer, not writer proof.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

from windows_network_toolkit.collectors.proxy_listener import (
    LocalProxyListener,
    check_local_proxy_listener,
)
from windows_network_toolkit.collectors.proxy_state import (
    DashboardProxyState,
    collect_dashboard_proxy_state,
)
from windows_network_toolkit.storage.event_store import EvidenceEventStore
from windows_network_toolkit.storage.events import (
    DEFAULT_LIMITATIONS,
    EvidenceEvent,
    new_event_id,
    utc_now_iso,
)

logger = logging.getLogger(__name__)


def _classify_and_tier(
    state: DashboardProxyState,
    listener: LocalProxyListener,
) -> tuple[str, str, float, list[str], list[str]]:
    """Rank classification via existing toolkit engines; never invent a second engine.

    Args:
        state: Current HKCU proxy snapshot.
        listener: Passive localhost listener evidence for the parsed port.

    Returns:
        Tuple of ``(classification_code, proof_tier, confidence, next_actions, limitations)``.

    Note:
        On engine failure, returns a coarse fallback code with reduced confidence and
        appends the exception string to limitations.
    """

    limitations = list(DEFAULT_LIMITATIONS)
    try:
        from src.platform_core.attribution.models import ProcessAttribution, ProxyStateSnapshot
        from src.platform_core.governance.proof_tier import resolve_proof_tier
        from windows_network_toolkit.proxy_classification import classify_from_snapshots

        snap = ProxyStateSnapshot(
            wininet_proxy_enable=int(state.proxy_enable or 0),
            wininet_proxy_server=str(state.proxy_server or ""),
            wininet_proxy_override=str(state.proxy_override or ""),
            wininet_auto_config_url=str(state.auto_config_url or ""),
            winhttp_raw="",
            winhttp_direct_access=True,
            localhost_port=state.localhost_port,
        )
        proc = ProcessAttribution(
            pid=listener.listener_pid,
            process_name=listener.listener_process_name or "",
        )
        result = classify_from_snapshots(
            snap,
            proc,
            listener_detected=listener.listener_present,
        )
        fixture = {
            "classification": {"primary_classification": result.primary_classification},
            "proxy_owner": {"listener_found": listener.listener_present},
            "proxy_state": {
                "wininet_proxy_enabled": state.is_enabled,
                "localhost_port": state.localhost_port,
            },
        }
        tier = resolve_proof_tier(fixture)
        limitations.extend(result.limitations or [])
        limitations.extend(tier.limitations or [])
        return (
            result.primary_classification,
            tier.proof_tier.value,
            float(result.confidence),
            list(result.recommended_next_actions or []),
            limitations,
        )
    except Exception as exc:  # noqa: BLE001 — soft-fail classification
        logger.warning("classification_failed: %s", exc)
        code = "UNKNOWN"
        if state.is_enabled and state.is_localhost_proxy and not listener.listener_present:
            code = "DEAD_PROXY_CONFIG"
        elif state.is_enabled and state.is_localhost_proxy and listener.listener_present:
            code = "LOCAL_PROXY_ACTIVE"
        elif not state.is_enabled:
            code = "PROXY_DISABLED"
        return (
            code,
            "T1_LOCAL_CONFIG_EVIDENCE",
            0.5,
            ["Collect more evidence"],
            limitations + [str(exc)],
        )


class ProxyWatcher:
    """Poll HKCU proxy state on an interval; append events only on change.

    Injectable collect/check/sleep callables support deterministic tests without live Windows.
    """

    def __init__(
        self,
        store: EvidenceEventStore,
        *,
        interval_seconds: float = 1.0,
        collect_state: Callable[..., DashboardProxyState] | None = None,
        check_listener: Callable[..., LocalProxyListener] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        on_event: Callable[[EvidenceEvent], None] | None = None,
    ) -> None:
        """Create an injectable read-only proxy watcher.

        Args:
            store: Evidence event store receiving baseline and change events.
            interval_seconds: Poll interval in seconds; clamped to a minimum of 0.2.
            collect_state: Optional proxy-state collector for tests.
            check_listener: Optional listener detector for tests.
            sleep_fn: Sleep callable used by the background loop.
            on_event: Optional callback invoked after an event is appended.

        Returns:
            None.

        Side effects:
            Initializes locks and thread state; does not start polling until ``start`` is called."""
        self.store = store
        self.interval_seconds = max(0.2, float(interval_seconds))
        self._collect_state = collect_state or collect_dashboard_proxy_state
        self._check_listener = check_listener or check_local_proxy_listener
        self._sleep = sleep_fn
        self._on_event = on_event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._prior: DashboardProxyState | None = None
        self._last_listener: LocalProxyListener | None = None
        self._last_classification: dict[str, Any] = {}
        self._status = "stopped"
        self._lock = threading.RLock()

    @property
    def status(self) -> str:
        """Return the current watcher lifecycle status.

        Args:
            None.

        Returns:
            Status string such as ``"stopped"`` or ``"running"``.

        Side effects:
            Acquires the watcher lock."""
        with self._lock:
            return self._status

    @property
    def last_state(self) -> DashboardProxyState | None:
        """Return the most recently observed proxy state.

        Args:
            None.

        Returns:
            Last ``DashboardProxyState`` observed, or ``None`` before the first poll.

        Side effects:
            Acquires the watcher lock."""
        with self._lock:
            return self._prior

    @property
    def last_listener(self) -> LocalProxyListener | None:
        """Return the most recent listener correlation result.

        Args:
            None.

        Returns:
            Last ``LocalProxyListener`` observed, or ``None`` before the first poll.

        Side effects:
            Acquires the watcher lock."""
        with self._lock:
            return self._last_listener

    @property
    def last_classification(self) -> dict[str, Any]:
        """Return a copy of the latest watcher classification payload.

        Args:
            None.

        Returns:
            Dict containing classification code, proof tier, confidence, next actions, and limitations.

        Side effects:
            Acquires the watcher lock."""
        with self._lock:
            return dict(self._last_classification)

    def start(self) -> None:
        """Start the daemon poll loop if not already running (idempotent)."""

        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._status = "running"
            self._thread = threading.Thread(
                target=self._loop, name="wnt-proxy-watcher", daemon=True
            )
            self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        """Signal the loop to exit and join the thread.

        Args:
            timeout: Join timeout in seconds; status is set to ``stopped`` regardless.
        """

        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        with self._lock:
            self._status = "stopped"

    def poll_once(self) -> EvidenceEvent | None:
        """Run one collect → classify → maybe-append cycle.

        Returns:
            The appended ``EvidenceEvent`` when state changed (or baseline); else ``None``.

        Side effects:
            Updates ``last_state`` / ``last_listener`` / ``last_classification``; may append.
        """

        state = self._collect_state()
        listener = self._check_listener(state.localhost_port if state.is_localhost_proxy else None)
        classification, proof_tier, confidence, actions, limitations = _classify_and_tier(
            state, listener
        )
        with self._lock:
            self._last_listener = listener
            self._last_classification = {
                "code": classification,
                "proof_tier": proof_tier,
                "confidence": confidence,
                "recommended_next_actions": actions,
                "limitations": limitations,
            }
            prior = self._prior
            changed = prior is None or prior.identity_tuple() != state.identity_tuple()
            self._prior = state
        if not changed:
            return None

        incident_id = f"inc-{uuid.uuid4().hex[:10]}"
        event = EvidenceEvent(
            event_id=new_event_id(),
            timestamp=utc_now_iso(),
            source="proxy_watcher",
            event_type="proxy_state_change" if prior is not None else "proxy_state_baseline",
            severity="warning" if state.is_enabled and state.is_localhost_proxy else "info",
            summary=(
                f"ProxyEnable={state.proxy_enable} server={state.proxy_server or '(empty)'} "
                f"listener={'yes' if listener.listener_present else 'no'}"
            ),
            data={
                "old": prior.to_dict() if prior else None,
                "new": state.to_dict(),
                "listener": listener.to_dict(),
                "process_name": listener.listener_process_name,
                "recommended_next_actions": actions,
            },
            incident_id=incident_id,
            classification=classification,
            proof_tier=proof_tier,
            confidence=confidence,
            limitations=limitations,
        )
        self.store.append(event)
        if self._on_event:
            self._on_event(event)
        return event

    def _loop(self) -> None:
        """Internal daemon thread body — runs ``poll_once`` on every interval tick."""
        try:
            while not self._stop.is_set():
                try:
                    self.poll_once()
                except Exception:  # noqa: BLE001
                    logger.exception("proxy_watcher_poll_failed")
                self._stop.wait(self.interval_seconds)
        finally:
            with self._lock:
                self._status = "stopped"
