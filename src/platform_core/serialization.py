"""Deterministic JSON serialization for platform_core."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def canonical_json(obj: Any) -> str:
    """Return canonical json.

    Args:
        obj: obj supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.
    """
    if isinstance(obj, BaseModel):
        payload = obj.model_dump(mode="json")
    else:
        payload = obj
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_hash(obj: Any) -> str:
    """Return content hash.

    Args:
        obj: obj supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.
    """
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
