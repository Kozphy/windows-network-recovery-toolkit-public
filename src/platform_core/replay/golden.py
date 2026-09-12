"""Golden replay fixtures."""

from __future__ import annotations

from pathlib import Path

GOLDEN_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "platform_core" / "golden"


def golden_cases() -> list[Path]:
    """Return golden cases.

    Returns:
        The computed `list[Path]` value.

    Side effects:
        None.
    """
    if not GOLDEN_DIR.is_dir():
        return []
    return sorted(GOLDEN_DIR.glob("*.jsonl"))
