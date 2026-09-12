"""Resolve canonical audit paths under ``WNT_AUDIT_DIR`` (default ``.audit``)."""

from __future__ import annotations

import os
from pathlib import Path

CANONICAL_AUDIT_FILENAME = "canonical_custody.jsonl"
TIP_ANCHOR_SCHEMA = "audit_tip_anchor.v1"


def audit_root() -> Path:
    """Return audit root directory from ``WNT_AUDIT_DIR`` or default ``.audit``."""
    raw = os.environ.get("WNT_AUDIT_DIR", ".audit")
    return Path(raw)


def default_canonical_path() -> Path:
    """Hash-chained custody JSONL path (Level 1 unified sink)."""
    return audit_root() / CANONICAL_AUDIT_FILENAME


def tip_path_for(audit_path: Path) -> Path:
    """Sibling tip anchor for an audit JSONL (``name.jsonl`` → ``name.tip.json``)."""
    return audit_path.with_name(f"{audit_path.stem}.tip.json")
