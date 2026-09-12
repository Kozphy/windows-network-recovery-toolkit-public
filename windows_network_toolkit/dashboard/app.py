"""NiceGUI + FastAPI local monitoring dashboard entrypoint.

Module responsibility:
    Compose ``DashboardConfig``, ``EvidenceEventStore``, and ``ProxyWatcher``, then
    start a loopback-bound NiceGUI UI for read-only proxy evidence monitoring.

System placement:
    Invoked by ``python -m windows_network_toolkit dashboard`` via ``cmd_dashboard``.
    Depends on optional ``nicegui`` / ``psutil`` extras (``pip install -e ".[dashboard]"``).

Key invariants:
    * Default bind host is ``127.0.0.1`` — never all interfaces unless the operator
      explicitly overrides and accepts exposure risk in the CLI.
    * The watcher never remediates (no registry writes, process kills, or firewall changes).
    * Shutdown stops the watcher cleanly via NiceGUI ``on_shutdown``.

Input assumptions:
    * ``DashboardConfig.validate()`` has been called (or is called inside helpers).
    * Optional kwargs mirror config fields when ``config`` is omitted.

Output guarantees:
    * ``create_runtime`` returns a wired ``DashboardRuntime`` without starting the HTTP server.
    * ``run_dashboard`` blocks until the UI process exits.

Side effects:
    * Starts a background watcher thread.
    * Binds an HTTP server on the configured host/port.
    * Appends evidence events to JSONL under ``WNT_AUDIT_DIR`` or ``storage_path``.

Failure modes:
    * Missing ``nicegui`` raises ``SystemExit`` with install guidance.
    * Invalid bind config raises ``ValueError`` before the server starts.

Audit Notes:
    * Review ``.audit/dashboard-events.jsonl`` (or ``--storage-path``) for watcher emissions.
    * Clear UI view does not delete persisted evidence — only hides rows in the ring buffer filter.

Engineering Notes:
    * NiceGUI is kept optional so core CLI installs stay light; dashboard is an extras path.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from windows_network_toolkit.collectors.proxy_watcher import ProxyWatcher
from windows_network_toolkit.dashboard.config import DashboardConfig
from windows_network_toolkit.dashboard.state import DashboardRuntime
from windows_network_toolkit.dashboard.views import build_dashboard
from windows_network_toolkit.storage.event_store import EvidenceEventStore

logger = logging.getLogger(__name__)


def create_runtime(config: DashboardConfig) -> DashboardRuntime:
    """Build store + watcher runtime without starting the HTTP server.

    Args:
        config: Validated dashboard configuration.

    Returns:
        ``DashboardRuntime`` with an unstarted or ready-to-start watcher.

    Raises:
        ValueError: Propagated from ``config.validate()``.
    """

    config.validate()
    store = EvidenceEventStore(
        max_visible=config.max_visible_events,
        storage_path=config.storage_path,
        persist=True,
    )
    watcher = ProxyWatcher(store, interval_seconds=config.watch_interval)
    return DashboardRuntime(config=config, store=store, watcher=watcher)


def run_dashboard(config: DashboardConfig | None = None, **kwargs: Any) -> None:
    """Start the local read-only dashboard (blocking).

    Args:
        config: Optional prebuilt config. When omitted, builds from kwargs:
            ``host``, ``port``, ``watch_interval``, ``max_visible_events``, ``storage_path``.
        **kwargs: Convenience overrides used only when ``config`` is None.

    Returns:
        None. Blocks until the UI server shuts down.

    Raises:
        ValueError: Invalid host/port/interval.
        SystemExit: When NiceGUI is not installed.

    Side effects:
        Starts ``ProxyWatcher``, registers UI pages, binds HTTP, persists evidence JSONL.
    """

    cfg = config or DashboardConfig(
        host=str(kwargs.get("host") or "127.0.0.1"),
        port=int(kwargs.get("port") or 8765),
        watch_interval=float(kwargs.get("watch_interval") or 1.0),
        max_visible_events=int(kwargs.get("max_visible_events") or 200),
        storage_path=Path(kwargs["storage_path"]) if kwargs.get("storage_path") else None,
    )
    cfg.validate()

    try:
        from nicegui import app, ui
    except ImportError as exc:
        raise SystemExit(
            "nicegui is required for the dashboard. Install with: "
            'pip install "nicegui" "psutil" '
            "or: pip install -e \".[dashboard]\""
        ) from exc

    runtime = create_runtime(cfg)
    runtime.watcher.start()

    @app.on_shutdown
    def _shutdown() -> None:
        logger.info("dashboard_shutdown_stopping_watcher")
        runtime.watcher.stop()

    build_dashboard(runtime)
    ui.run(
        host=cfg.host,
        port=cfg.port,
        title=cfg.title,
        reload=False,
        show=False,
    )
