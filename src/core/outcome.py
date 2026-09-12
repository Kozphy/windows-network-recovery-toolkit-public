"""DEPRECATED: use ``src.platform.models``."""

from __future__ import annotations

import warnings

from src.platform.models import DecisionOutcome

warnings.warn("src.core.outcome is deprecated; use src.platform.models", DeprecationWarning, stacklevel=2)

__all__ = ["DecisionOutcome"]
