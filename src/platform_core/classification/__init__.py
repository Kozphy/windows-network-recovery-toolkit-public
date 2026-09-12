"""Canonical proxy classification engine."""

from src.platform_core.classification.engine import classify_proxy
from src.platform_core.classification.models import PrimaryClassification, SecondarySignal

__all__ = ["PrimaryClassification", "SecondarySignal", "classify_proxy"]
