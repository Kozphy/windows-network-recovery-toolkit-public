"""Append-only evidence event store for the local monitoring dashboard.

Module responsibility:
    Keep a thread-safe in-memory ring buffer of ``EvidenceEvent`` rows and optionally
    persist each append as one JSONL line for audit review.

System placement:
    Used by ``ProxyWatcher``, ``cmd_procmon_import``, and dashboard views.

Key invariants:
    * Persistence is append-only — ``clear_ui_view`` never deletes JSONL rows.
    * ``max_visible`` bounds only the in-memory deque; disk history may be longer.
    * Default path is ``audit_dir() / dashboard-events.jsonl`` via ``append_audit_dict``.

Side effects:
    * Creates parent directories for ``storage_path`` when set.
    * Writes one JSON line per ``append`` when ``persist=True``.

Idempotency:
    * Re-appending the same logical observation creates a new event id (not deduped).
    * ``start`` of the watcher is idempotent if the thread is already alive (caller side).

Failure modes:
    * Disk full / permission errors on write propagate to the caller.
    * Concurrent ``append`` / ``recent`` are serialized by an ``RLock``.

Audit Notes:
    * What could go wrong: UI "Clear" misread as evidence deletion.
    * Detection: compare UI row count vs JSONL line count under ``WNT_AUDIT_DIR``.
    * Recovery: re-open dashboard or ``procmon-import``; do not truncate JSONL for ops.
    * Evidence: ``.audit/dashboard-events.jsonl`` or ``--storage-path``.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from pathlib import Path

from windows_network_toolkit.audit_store import append_audit_dict, audit_dir
from windows_network_toolkit.storage.events import EvidenceEvent


class EvidenceEventStore:
    """Thread-safe in-memory ring buffer plus optional JSONL persistence."""

    def __init__(
        self,
        *,
        max_visible: int = 200,
        storage_path: Path | None = None,
        persist: bool = True,
        audit_log_name: str = "dashboard-events.jsonl",
    ) -> None:
        """Create a store.

        Args:
            max_visible: Ring-buffer capacity (clamped to at least 10).
            storage_path: Explicit JSONL path. When None and persist is True, uses
                ``append_audit_dict`` with ``audit_log_name``.
            persist: When False, memory-only (tests).
            audit_log_name: Filename under the audit directory when ``storage_path`` is None.
        """

        self.max_visible = max(10, int(max_visible))
        self.storage_path = storage_path
        self.persist = persist
        self.audit_log_name = audit_log_name
        self._lock = threading.RLock()
        self._events: deque[EvidenceEvent] = deque(maxlen=self.max_visible)
        self._ui_cleared_ids: set[str] = set()

    def append(self, event: EvidenceEvent) -> EvidenceEvent:
        """Append one event to memory and optionally to JSONL.

        Args:
            event: Normalized evidence event.

        Returns:
            The same ``event`` instance for chaining.

        Side effects:
            May create directories and append one UTF-8 JSON line.
        """

        with self._lock:
            self._events.append(event)
            if self.persist:
                if self.storage_path is not None:
                    self.storage_path.parent.mkdir(parents=True, exist_ok=True)
                    with self.storage_path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
                else:
                    append_audit_dict(event.to_dict(), log_name=self.audit_log_name)
            return event

    def recent(self, *, include_cleared: bool = False, limit: int | None = None) -> list[EvidenceEvent]:
        """Return chronological events for the UI, optionally excluding cleared ids.

        Args:
            include_cleared: When True, ignore the UI clear filter.
            limit: If set, return only the last N matching events.

        Returns:
            A new list (safe to mutate by callers).
        """

        with self._lock:
            items = list(self._events)
        if not include_cleared:
            items = [e for e in items if e.event_id not in self._ui_cleared_ids]
        if limit is not None:
            items = items[-max(1, limit) :]
        return items

    def clear_ui_view(self) -> None:
        """Hide currently buffered events from UI without deleting persisted evidence."""

        with self._lock:
            self._ui_cleared_ids.update(e.event_id for e in self._events)

    def filter(
        self,
        *,
        severity: str | None = None,
        source: str | None = None,
        process_name: str | None = None,
        limit: int | None = None,
    ) -> list[EvidenceEvent]:
        """Return recent events matching optional UI filters (case-insensitive).

        Args:
            severity: Exact severity match when non-empty.
            source: Exact source match when non-empty.
            process_name: Substring match against ``data.process_name`` or listener name.
            limit: Optional trailing-window limit after filters.

        Returns:
            Filtered list of events.
        """

        rows = self.recent(limit=None)
        if severity:
            sev = severity.lower()
            rows = [e for e in rows if (e.severity or "").lower() == sev]
        if source:
            src = source.lower()
            rows = [e for e in rows if (e.source or "").lower() == src]
        if process_name:
            needle = process_name.lower()
            rows = [
                e
                for e in rows
                if needle
                in str(e.data.get("process_name") or e.data.get("listener_process_name") or "").lower()
            ]
        if limit is not None:
            rows = rows[-max(1, limit) :]
        return rows

    def default_storage_dir(self) -> Path:
        """Return the toolkit audit directory used when ``storage_path`` is unset."""

        return audit_dir()
