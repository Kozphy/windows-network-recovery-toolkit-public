"""Signal collectors — thin read-only facades over src/proxy_guard and network_agent.

Module responsibility:
    Aggregate all endpoint evidence collectors into a single importable surface.
    Each sub-module is a thin facade: it delegates to the corresponding
    ``src/proxy_guard`` or ``src/observability`` implementation and returns a
    plain ``dict`` safe for JSON serialisation.

System placement:
    Imported by the analytics pipeline, CLI commands, and the monitoring
    dashboard. No collector in this package writes state, modifies the registry,
    or opens outbound sockets beyond what the underlying probe already does.

Key invariants:
    * All public functions are soft-fail: an unresolvable dependency or
      platform restriction returns an empty/default dict, never an uncaught
      exception (unless explicitly documented otherwise).
    * Collector outputs are raw evidence dicts — they carry a ``source`` key
      and must be fed through the classification engine before any conclusion
      is drawn.

Side effects:
    None at import time. Live OS queries happen only when a collector function
    is called without an ``inject``/``run`` override.
"""

from .browser_collector import collect_browser_signals
from .dns_collector import collect_dns_signals
from .eventlog_collector import collect_eventlog_signals
from .netstat_collector import collect_netstat_signals
from .process_collector import collect_process_signals
from .proxy_registry_collector import collect_proxy_registry

__all__ = [
    "collect_browser_signals",
    "collect_dns_signals",
    "collect_eventlog_signals",
    "collect_netstat_signals",
    "collect_process_signals",
    "collect_proxy_registry",
]
