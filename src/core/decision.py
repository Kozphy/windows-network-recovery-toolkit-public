"""DEPRECATED: use ``src.platform.models``."""

from __future__ import annotations

import warnings

from src.platform.models import ActionType, DecisionOption, Hypothesis

warnings.warn("src.core.decision is deprecated; use src.platform.models", DeprecationWarning, stacklevel=2)

__all__ = ["ActionType", "DecisionOption", "Hypothesis"]
