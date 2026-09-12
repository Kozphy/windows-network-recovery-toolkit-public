"""Shared dashboard runtime state (injected; avoid module-level mutables in logic).

Module responsibility:
    Hold the live ``EvidenceEventStore``, ``ProxyWatcher``, UI pause flag, and filters
    for NiceGUI views without scattering globals across modules.

System placement:
    Created by ``dashboard.app.create_runtime``; read by ``dashboard.views``.

Key invariants:
    * ``paused`` only stops the watcher from the UI — it does not delete evidence.
    * ``overview_payload`` is observational JSON for cards; classification fields may be empty
      until the first watcher poll completes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from windows_network_toolkit.collectors.proxy_watcher import ProxyWatcher
from windows_network_toolkit.dashboard.config import DashboardConfig
from windows_network_toolkit.storage.event_store import EvidenceEventStore


@dataclass
class DashboardRuntime:
    """Mutable UI/runtime handle for one dashboard process.

    Attributes:
        config: Launch configuration.
        store: Append-only evidence store with UI clear filter.
        watcher: Background HKCU proxy change watcher.
        paused: When True, UI requested watcher stop.
        selected_incident_id: Optional incident focus for detail pane.
        filters: Reserved UI filter bag (severity/source/process).
        ui_notes: Operator-facing epistemic reminders shown in the UI.
    """

    config: DashboardConfig
    store: EvidenceEventStore
    watcher: ProxyWatcher
    paused: bool = False
    selected_incident_id: str | None = None
    filters: dict[str, str] = field(default_factory=dict)
    ui_notes: list[str] = field(
        default_factory=lambda: [
            "Dashboard is read-only: no proxy disable, registry write, process kill, or evidence delete.",
            "A directly observed process operation does not prove human intent.",
        ]
    )

    def overview_payload(self) -> dict[str, Any]:
        """Build Overview card values from the latest watcher snapshot.

        Returns:
            JSON-serializable dict with proxy, listener, classification, and collector status.
            Missing snapshots yield ``None`` fields rather than inventing defaults.
        """

        state = self.watcher.last_state
        listener = self.watcher.last_listener
        classification = self.watcher.last_classification
        events = self.store.recent(limit=1)
        last_change = events[-1].timestamp if events else None
        return {
            "proxy_enabled": state.is_enabled if state else None,
            "proxy_server": state.proxy_server if state else None,
            "pac_url": state.auto_config_url if state else None,
            "local_listener": (
                {
                    "present": listener.listener_present,
                    "pid": listener.listener_pid,
                    "name": listener.listener_process_name,
                    "address": listener.listener_address,
                    "port": listener.listener_port,
                }
                if listener
                else None
            ),
            "classification": classification.get("code"),
            "proof_tier": classification.get("proof_tier"),
            "confidence": classification.get("confidence"),
            "collector_status": self.watcher.status,
            "paused": self.paused,
            "last_change": last_change,
            "limitations": classification.get("limitations") or self.ui_notes,
        }
