"""Evidence-bundle and timeline export to JSON files.

Module responsibility:
    Serialises evidence bundles and timeline lists to indented JSON files on disk.
    Accepts either Pydantic models (``model_dump()``) or plain dicts so callers
    do not need to pre-serialise.

System placement:
    Called by the ``export`` CLI command and by operator scripts that persist
    evidence for downstream audit or SIEM ingestion.

Key invariants:
    Parent directories are created automatically (``mkdir parents=True``).
    Existing files at the target path are overwritten without warning.

Side effects:
    Writes JSON files to disk at the specified paths.

Failure modes:
    ``PermissionError`` or ``OSError`` if the target path is not writable.
    ``TypeError`` if the bundle is neither a Pydantic model nor dict-castable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def export_evidence(bundle: Any, path: Path | str) -> Path:
    """Serialise an evidence bundle to an indented JSON file.

    Args:
        bundle: A Pydantic model (``model_dump()`` called automatically) or any
            object that can be passed to ``dict()``.
        path: Destination file path.  Parent directories are created if absent.

    Returns:
        The resolved ``Path`` object for the written file.

    Side effects:
        Creates parent directories; writes or overwrites the target JSON file.

    Raises:
        OSError: If the file cannot be written due to permissions or path issues.
        TypeError: If ``bundle`` is neither a Pydantic model nor dict-castable.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = bundle.model_dump() if hasattr(bundle, "model_dump") else dict(bundle)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def export_timeline(timeline: list[dict[str, Any]], path: Path | str) -> Path:
    """Serialise an ordered timeline list to an indented JSON file.

    Args:
        timeline: List of audit-record dicts to write.  Records are written in
            the order supplied; no sorting is applied here.
        path: Destination file path.  Parent directories are created if absent.

    Returns:
        The resolved ``Path`` object for the written file.

    Side effects:
        Creates parent directories; writes or overwrites the target JSON file.

    Raises:
        OSError: If the file cannot be written due to permissions or path issues.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    return p
