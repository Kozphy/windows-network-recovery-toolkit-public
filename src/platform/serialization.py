"""Deterministic JSON serialization."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def canonical_json(obj: Any) -> str:
    """Canonical json.
    
    Args:
        obj: The obj value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if isinstance(obj, BaseModel):
        payload = obj.model_dump(mode="json")
    else:
        payload = obj
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_hash(obj: Any) -> str:
    """Content hash.
    
    Args:
        obj: The obj value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
