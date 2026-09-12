"""Process/TCP attribution parsers used by Proxy Guard and snapshot assembly.

Submodules stay side-effect free unless a named ``capture_*`` helper is invoked indirectly
from observability callers.
"""

from .port_owner import netstat_listen_rows, owners_for_port
from .process_tree import parse_simple_process_block
from .suspicious_process import diagnostic_suspicion_tier

__all__ = [
    "diagnostic_suspicion_tier",
    "netstat_listen_rows",
    "owners_for_port",
    "parse_simple_process_block",
]
