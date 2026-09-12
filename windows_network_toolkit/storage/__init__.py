"""Storage package — schema and append-only store for dashboard evidence events.

Module responsibility:
    Re-export the key storage surface used by collectors, the monitoring
    dashboard, and the proxy watcher: the ``EvidenceEvent`` schema, the
    append-only ``EvidenceEventStore``, and utility helpers
    (``new_event_id``, ``utc_now_iso``, ``DEFAULT_LIMITATIONS``).

System placement:
    Imported by ``collectors/proxy_watcher.py``, dashboard views, and any
    module that appends or queries ``EvidenceEvent`` rows.  Implementation
    lives in ``storage/events.py`` (schema) and ``storage/event_store.py``
    (store).

Key invariants:
    * ``EvidenceEventStore`` is append-only; events are never mutated or
      deleted after being appended.
    * ``DEFAULT_LIMITATIONS`` carries the epistemic boundary statements that
      every evidence event must include.
    * This ``__init__`` re-exports only; no logic or state lives here.

Side effects:
    None at import time.
"""

from windows_network_toolkit.storage.event_store import EvidenceEventStore
from windows_network_toolkit.storage.events import (
    DEFAULT_LIMITATIONS,
    EvidenceEvent,
    new_event_id,
    utc_now_iso,
)

__all__ = [
    "DEFAULT_LIMITATIONS",
    "EvidenceEvent",
    "EvidenceEventStore",
    "new_event_id",
    "utc_now_iso",
]
