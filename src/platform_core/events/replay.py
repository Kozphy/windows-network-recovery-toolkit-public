"""Deterministic replay of trisk domain events from fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.platform_core.events.models import TriskDomainEvent
from src.platform_core.events.store import TriskEventStore, reset_event_store


def replay_events(fixture_path: Path, *, out_path: Path | None = None) -> list[dict[str, Any]]:
    """Re-emit events from a JSONL fixture into a fresh store (tests)."""
    reset_event_store()
    store = TriskEventStore(path=out_path)
    emitted: list[dict[str, Any]] = []
    for line in fixture_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)
        event = TriskDomainEvent.model_validate(raw)
        store.append(event)
        emitted.append(event.model_dump(mode="json"))
    return emitted
