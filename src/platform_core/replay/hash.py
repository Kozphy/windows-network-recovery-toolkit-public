"""Stable replay output hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def stable_hash(payload: dict[str, Any]) -> str:
    """Return stable hash.

    Args:
        payload: payload supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
