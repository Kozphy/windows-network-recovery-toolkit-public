"""DEPRECATED: use ``src.platform.serialization``."""

from __future__ import annotations

import warnings

from pydantic import BaseModel

from src.platform.serialization import canonical_json, content_hash

warnings.warn(
    "src.core.serialization is deprecated; use src.platform.serialization",
    DeprecationWarning,
    stacklevel=2,
)


def json_schema(model: type[BaseModel]) -> dict:
    """Json schema.

    Args:
        model: The model value supplied by the caller.

    Returns:
        The dict result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return model.model_json_schema()


__all__ = ["canonical_json", "content_hash", "json_schema"]
