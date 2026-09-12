"""Append-only UX-oriented events emitted by Network State CLI surfaces.

Feeds ``logs/network_state_events.jsonl`` for future tray/daemon ingestion and reporting rollups (`network-state report` scans this stream).

Constraints:
    * Payloads intentionally avoid machine identifiers beyond what proxy configuration literals already imply.
    * Event taxonomy is enumerated via typing literal for static checks.

Malformed consumers:
    Downstream scanners should tolerate partial JSON writes identical to general JSONL guidance (skip corrupt lines).

Raises:
    None from emitter — IO failures propagate as ``OSError`` only.

Audit Notes:
    Compare ``event_id`` monotonic timelines with drift detections logged elsewhere when reconciling flaky automation triggering duplicate ``drift_detected`` rows.

See Also:
    :mod:`report` aggregator for ingestion semantics.

"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal

from ..core.time_utils import utc_now_iso
from .paths import events_jsonl

EventType = Literal[
    "snapshot_saved",
    "drift_detected",
    "policy_decision",
    "rollback_previewed",
    "rollback_applied",
    "evidence_imported",
    "report_generated",
]


def emit_network_state_event(
    repo_root: Path,
    event_type: EventType,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Append one JSON line to ``logs/network_state_events.jsonl``.

    Args:
        repo_root: Toolkit checkout root honoring ``--repo-root``.
        event_type: Canonical label matching literal union for grep-friendly dashboards.
        payload: JSON-serializable dict (trim large blobs before invoking).

    Returns:
        Persisted envelope including deterministic ``schema_version``.

    Side effects:
        Creates ``logs`` directory as needed.

    Raises:
        ``TypeError``: Non-JSON-serializable nested values.
        ``OSError``: Append failures only.

    Idempotency:
        Each emission is unique UUID — duplicate logical events still append independently.
    """
    row: dict[str, Any] = {
        "schema_version": 1,
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "timestamp_utc": utc_now_iso(),
        "payload": payload,
    }
    path = events_jsonl(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row
