"""NiceGUI views for the read-only monitoring dashboard.

Module responsibility:
    Register the single-page UI: Overview cards, evidence timeline, pause/resume,
    UI-only clear, process snapshot table, and incident detail markdown.

System placement:
    Called once from ``run_dashboard`` after the watcher starts.

Key invariants:
    * No remediation buttons (no proxy disable, registry write, process kill).
    * Clear UI view calls ``store.clear_ui_view`` only — does not delete JSONL.
    * Pause/Resume stop/start the watcher thread; they do not mutate Windows state.

Side effects:
    * Registers NiceGUI page handlers and timers; may call ``psutil`` via process snapshot.
"""

from __future__ import annotations

from typing import Any

from windows_network_toolkit.collectors.process_snapshot import collect_process_snapshot
from windows_network_toolkit.dashboard.state import DashboardRuntime


def _safe_ui():
    from nicegui import ui

    return ui


def build_dashboard(runtime: DashboardRuntime) -> None:
    """Register NiceGUI pages/components bound to *runtime*.

    Args:
        runtime: Live config, store, and watcher handle for this process.

    Side effects:
        Defines the ``/`` page and UI timers; does not bind the HTTP server (``ui.run`` does).
    """

    ui = _safe_ui()

    @ui.page("/")
    def index() -> None:  # noqa: ANN202
        """Render the dashboard root page.

        Args:
            None.

        Returns:
            None.

        Side effects:
            Constructs NiceGUI components, registers callbacks, and starts a refresh timer."""
        ui.dark_mode().enable()
        ui.page_title(runtime.config.title)
        with ui.header().classes("items-center justify-between"):
            ui.label(runtime.config.title).classes("text-h6")
            ui.label("READ-ONLY").classes("text-negative text-bold")
        with ui.row().classes("w-full q-pa-md gap-4"):
            with ui.column().classes("w-full"):
                ui.label("Overview").classes("text-h5")
                cards = ui.row().classes("w-full flex-wrap gap-3")
                timeline_table = ui.table(
                    columns=[
                        {"name": "time", "label": "Time", "field": "time"},
                        {"name": "source", "label": "Source", "field": "source"},
                        {"name": "event", "label": "Event", "field": "event"},
                        {"name": "process", "label": "Process", "field": "process"},
                        {"name": "old", "label": "Old value", "field": "old"},
                        {"name": "new", "label": "New value", "field": "new"},
                        {"name": "classification", "label": "Classification", "field": "classification"},
                        {"name": "proof_tier", "label": "Proof tier", "field": "proof_tier"},
                        {"name": "severity", "label": "Severity", "field": "severity"},
                    ],
                    rows=[],
                    row_key="event_id",
                ).classes("w-full")
                with ui.row().classes("gap-2 items-center"):
                    pause_btn = ui.button("Pause")
                    resume_btn = ui.button("Resume")
                    clear_btn = ui.button("Clear UI view")
                    sev = ui.select(["", "info", "warning", "error"], label="Severity", value="")
                    src = ui.input(label="Source filter")
                    proc = ui.input(label="Process filter")
                ui.separator()
                ui.label("Process Snapshot").classes("text-h5")
                proc_table = ui.table(
                    columns=[
                        {"name": "pid", "label": "PID", "field": "pid"},
                        {"name": "ppid", "label": "PPID", "field": "ppid"},
                        {"name": "name", "label": "Name", "field": "name"},
                        {"name": "executable", "label": "Executable", "field": "executable"},
                        {"name": "command_line", "label": "Command line", "field": "command_line"},
                        {"name": "username", "label": "Username", "field": "username"},
                        {"name": "tcp_endpoints", "label": "TCP endpoints", "field": "tcp_endpoints"},
                    ],
                    rows=[],
                    row_key="pid",
                ).classes("w-full")
                ui.separator()
                ui.label("Incident Detail").classes("text-h5")
                detail = ui.markdown("Select a timeline row or wait for the next proxy change.")
                for note in runtime.ui_notes:
                    ui.label(note).classes("text-caption text-grey-5")

        def refresh() -> None:
            """Refresh overview cards, evidence timeline, process snapshot, and detail panel.

            Args:
                None.

            Returns:
                None.

            Side effects:
                Reads runtime/store state, may collect process snapshots, and updates NiceGUI widgets."""
            ov = runtime.overview_payload()
            cards.clear()
            with cards:
                _card(ui, "Proxy enabled", str(ov.get("proxy_enabled")))
                _card(ui, "Proxy server", str(ov.get("proxy_server") or "(empty)"))
                _card(ui, "PAC URL", str(ov.get("pac_url") or "(empty)"))
                loc = ov.get("local_listener") or {}
                _card(
                    ui,
                    "Local listener",
                    (
                        f"{'yes' if loc.get('present') else 'no'} "
                        f"pid={loc.get('pid')} {loc.get('name') or ''}".strip()
                    ),
                )
                _card(ui, "Classification", str(ov.get("classification") or "—"))
                _card(ui, "Proof tier", str(ov.get("proof_tier") or "—"))
                _card(ui, "Collector status", str(ov.get("collector_status")))
                _card(ui, "Last change", str(ov.get("last_change") or "—"))

            events = runtime.store.filter(
                severity=sev.value or None,
                source=src.value or None,
                process_name=proc.value or None,
                limit=runtime.config.max_visible_events,
            )
            rows = []
            for e in reversed(events):
                old = (e.data.get("old") or {}) if isinstance(e.data.get("old"), dict) else {}
                new = (e.data.get("new") or {}) if isinstance(e.data.get("new"), dict) else {}
                rows.append(
                    {
                        "event_id": e.event_id,
                        "time": e.timestamp,
                        "source": e.source,
                        "event": e.event_type,
                        "process": e.data.get("process_name") or e.data.get("listener_process_name") or "",
                        "old": old.get("proxy_server") if old else "",
                        "new": new.get("proxy_server") if new else e.summary[:80],
                        "classification": e.classification or "",
                        "proof_tier": e.proof_tier or "",
                        "severity": e.severity,
                    }
                )
            timeline_table.rows = rows
            timeline_table.update()

            listener = runtime.watcher.last_listener
            pids = []
            if listener and listener.listener_pid:
                pids.append(listener.listener_pid)
            for e in events[-5:]:
                pid = e.data.get("pid") or (e.data.get("listener") or {}).get("listener_pid")
                if isinstance(pid, int):
                    pids.append(pid)
            snap = collect_process_snapshot(pids)
            proc_rows = []
            for p in snap.get("processes") or []:
                proc_rows.append(
                    {
                        "pid": p.get("pid"),
                        "ppid": p.get("ppid"),
                        "name": p.get("name"),
                        "executable": p.get("executable"),
                        "command_line": (p.get("command_line") or "")[:120],
                        "username": p.get("username"),
                        "tcp_endpoints": ", ".join(p.get("tcp_endpoints") or [])[:120],
                    }
                )
            proc_table.rows = proc_rows
            proc_table.update()

            latest = events[-1] if events else None
            if latest:
                detail.set_content(_incident_markdown(latest, ov))

        def on_pause() -> None:
            """Pause the watcher from the dashboard UI.

            Args:
                None.

            Returns:
                None.

            Side effects:
                Sets runtime pause state, stops the watcher thread, and refreshes widgets."""
            runtime.paused = True
            runtime.watcher.stop()
            refresh()

        def on_resume() -> None:
            """Resume the watcher from the dashboard UI.

            Args:
                None.

            Returns:
                None.

            Side effects:
                Clears runtime pause state, starts the watcher thread, and refreshes widgets."""
            runtime.paused = False
            runtime.watcher.start()
            refresh()

        def on_clear() -> None:
            """Clear the in-memory dashboard event view.

            Args:
                None.

            Returns:
                None.

            Side effects:
                Calls ``store.clear_ui_view()`` and refreshes widgets; persisted JSONL evidence is not deleted."""
            runtime.store.clear_ui_view()
            refresh()

        pause_btn.on_click(on_pause)
        resume_btn.on_click(on_resume)
        clear_btn.on_click(on_clear)
        ui.timer(1.0, refresh)
        refresh()


def _card(ui: Any, title: str, value: str) -> None:
    with ui.card().classes("q-pa-md").style("min-width: 180px"):
        ui.label(title).classes("text-caption text-grey-6")
        ui.label(value).classes("text-subtitle1")


def _incident_markdown(event: Any, overview: dict[str, Any]) -> str:
    data = event.data or {}
    actions = data.get("recommended_next_actions") or []
    action = actions[0] if actions else "Continue observation; use policy-gated remediation CLIs separately."
    return f"""
### Incident `{event.incident_id or event.event_id}`

**Observations**
- Summary: {event.summary}
- Source: `{event.source}` / `{event.event_type}`

**State transition**
- Old: `{data.get('old')}`
- New: `{data.get('new')}`

**Listener verification**
- `{data.get('listener') or overview.get('local_listener')}`

**Classification / proof**
- Classification: `{event.classification}`
- Proof tier: `{event.proof_tier}`
- Confidence: `{event.confidence}` (ordinal, not calibrated probability)

**Limitations**
{chr(10).join('- ' + lim for lim in (event.limitations or [])[:6])}

**Recommended next diagnostic action**
- {action}

> A directly observed process operation does not prove human intent.
"""
