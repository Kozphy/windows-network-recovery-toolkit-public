"""Dashboard configuration (localhost-only by default).

Module responsibility:
    Hold immutable bind/watch/UI limits for the monitoring dashboard and validate
    unsafe bind hosts before the server starts.

System placement:
    Consumed by ``dashboard.app.create_runtime`` and ``cmd_dashboard``.

Key invariants:
    * ``host`` must not be an all-interfaces wildcard unless the CLI explicitly allows it
      (validation here rejects ``0.0.0.0`` / ``::``).
    * ``watch_interval`` must be >= 0.2 seconds to avoid busy loops.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DashboardConfig:
    """Immutable dashboard launch settings.

    Attributes:
        host: Bind address (default ``127.0.0.1``).
        port: Bind port (default ``8765``).
        watch_interval: Proxy watcher poll interval in seconds.
        max_visible_events: UI ring-buffer size for the timeline table.
        storage_path: Optional JSONL path; when None, uses ``.audit/dashboard-events.jsonl``.
        title: Browser / window title string.
    """

    host: str = "127.0.0.1"
    port: int = 8765
    watch_interval: float = 1.0
    max_visible_events: int = 200
    storage_path: Path | None = None
    title: str = "Windows Network Toolkit — Monitoring Dashboard"

    def validate(self) -> None:
        """Reject unsafe bind hosts and invalid numeric limits.

        Raises:
            ValueError: When host is all-interfaces, port is out of range, or interval is too small.
        """

        if self.host in {"0.0.0.0", "::", "[::]"}:
            raise ValueError(
                "Refusing to bind dashboard to all interfaces by default. "
                "Use an explicit loopback host such as 127.0.0.1."
            )
        if not (1 <= int(self.port) <= 65535):
            raise ValueError(f"Invalid dashboard port: {self.port}")
        if self.watch_interval < 0.2:
            raise ValueError("watch_interval must be >= 0.2 seconds")
