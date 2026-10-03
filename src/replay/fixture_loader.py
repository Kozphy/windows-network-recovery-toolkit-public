"""Load proxy incident fixtures for portable demo/CI replay."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "proxy_incidents"


def list_fixture_paths(directory: Path | None = None) -> list[Path]:
    """List fixture paths.

    Args:
        directory: The directory value supplied by the caller.

    Returns:
        The list[Path] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    root = directory or FIXTURES_DIR
    if not root.is_dir():
        return []
    return sorted(root.glob("*.json"))


def load_fixture(path: Path | str) -> dict[str, Any]:
    """Load fixture.

    Args:
        path: Filesystem path used by the operation.

    Returns:
        The dict[str, Any] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    p = Path(path)
    blob = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(blob, dict):
        raise ValueError(f"Fixture must be a JSON object: {p}")
    blob.setdefault("incident_id", p.stem)
    return blob


def load_all_fixtures(directory: Path | None = None) -> list[dict[str, Any]]:
    """Load all fixtures.

    Args:
        directory: The directory value supplied by the caller.

    Returns:
        The list[dict[str, Any]] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return [load_fixture(p) for p in list_fixture_paths(directory)]
