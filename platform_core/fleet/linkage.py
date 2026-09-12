"""Cross-package linkage between platform FailureEvent rows and failure_system JSONL shards."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class FleetConfigStub:
    """Placeholder fleet configuration (local prototype; no remote control)."""

    enabled: bool = False


def failure_system_blocks_dir() -> Path:
    """Resolve the Failure Knowledge JSONL directory for cross-package linkage."""
    from failure_system.storage import default_data_dir

    raw = os.environ.get("FAILURE_SYSTEM_DATA_DIR")
    if raw:
        return Path(raw).resolve()
    return default_data_dir()


def linked_failure_block_payload(failure_block_id: str) -> dict[str, Any]:
    """Best-effort load of a FailureBlock summary for linkage to ``FailureEvent``."""
    raw = (failure_block_id or "").strip()
    if not raw:
        return {"found": False, "failure_block_id": "", "detail": "no_failure_block_id"}

    try:
        uid = UUID(raw)
    except ValueError:
        return {"found": False, "failure_block_id": raw, "detail": "invalid_failure_block_uuid"}

    try:
        from failure_system.models import failure_block_to_summary
        from failure_system.storage import load_failure_block_by_id
    except ImportError:
        return {"found": False, "failure_block_id": raw, "detail": "failure_system_unavailable"}

    block = load_failure_block_by_id(uid, failure_system_blocks_dir())
    if block is None:
        return {
            "found": False,
            "failure_block_id": raw,
            "detail": "not_in_local_failure_kb",
        }

    summary = failure_block_to_summary(block)
    return {
        "found": True,
        "failure_block_id": raw,
        "failure_block_summary": summary.model_dump(mode="json"),
    }
