"""Resolve canonical audit paths under ``WNT_AUDIT_DIR`` (default ``.audit``)."""

from __future__ import annotations

import os
from pathlib import Path

CANONICAL_AUDIT_FILENAME = "canonical_custody.jsonl"
TIP_ANCHOR_SCHEMA = "audit_tip_anchor.v1"


def audit_root() -> Path:
    """Resolve the canonical audit directory.

    Returns:
        The path from ``WNT_AUDIT_DIR`` when set, otherwise ``.audit`` relative
        to the current working directory.

    Side effects:
        None. The directory is created by writers, not by this resolver.
    """
    raw = os.environ.get("WNT_AUDIT_DIR", ".audit")
    return Path(raw)


def default_canonical_path() -> Path:
    """Return the default Level 1 hash-chained custody JSONL path.

    Returns:
        ``audit_root() / canonical_custody.jsonl``.

    Side effects:
        None.
    """
    return audit_root() / CANONICAL_AUDIT_FILENAME


def tip_path_for(audit_path: Path) -> Path:
    """Return the sibling tip-anchor path for an audit JSONL file.

    Args:
        audit_path: Audit JSONL path whose stem names the tip file.

    Returns:
        A path using the deterministic rule ``name.jsonl`` -> ``name.tip.json``.

    Side effects:
        None.
    """
    return audit_path.with_name(f"{audit_path.stem}.tip.json")
