"""Concrete domain adapter implementations registered by :mod:`platform_core.decision_platform.registry`."""

from .cloud import CloudAdapter
from .infrastructure import InfrastructureAdapter
from .market import MarketAdapter
from .security import SecurityAdapter
from .windows import WindowsAdapter

__all__ = [
    "CloudAdapter",
    "InfrastructureAdapter",
    "MarketAdapter",
    "SecurityAdapter",
    "WindowsAdapter",
]
