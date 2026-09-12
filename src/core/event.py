"""DEPRECATED: use ``src.platform.models``."""

from __future__ import annotations

import warnings

from src.platform.models import DomainName, NormalizedEvent

warnings.warn("src.core.event is deprecated; use src.platform.models", DeprecationWarning, stacklevel=2)

__all__ = ["DomainName", "NormalizedEvent"]
