"""DEPRECATED: use ``src.platform.models.PolicyStatus``."""

from __future__ import annotations

import warnings

from src.platform.models import PolicyStatus

warnings.warn("src.core.policy is deprecated; use src.platform.models", DeprecationWarning, stacklevel=2)

__all__ = ["PolicyStatus"]
