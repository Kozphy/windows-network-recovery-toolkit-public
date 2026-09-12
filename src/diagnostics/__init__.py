"""Diagnostics layer: normalized ``FeatureVector`` and `collect_features`/`load_*` helpers."""

from .collector import collect_features
from .features import FeatureVector

__all__ = ["FeatureVector", "collect_features"]
