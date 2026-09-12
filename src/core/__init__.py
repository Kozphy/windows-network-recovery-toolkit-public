"""Stable exports for snapshots, nominal results, and UTC auditing helpers.

Downstream callers import ``src.core`` aliases to remain stdlib-only without deep paths.
"""

from .models import LiveNetworkSnapshot, ParsedProxy, PortOwnerRecord, ProxyRegistrySnapshot
from .result import Err, Ok, Result
from .time_utils import utc_now_iso

__all__ = [
    "Err",
    "LiveNetworkSnapshot",
    "Ok",
    "ParsedProxy",
    "PortOwnerRecord",
    "ProxyRegistrySnapshot",
    "Result",
    "utc_now_iso",
]
