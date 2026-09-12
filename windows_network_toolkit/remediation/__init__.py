"""Policy-gated remediation previews for the windows_network_toolkit package.

Module responsibility:
    Re-exports the five ``preview_*`` functions that describe remediation actions
    in a structured dict without executing them.  All functions default to
    ``dry_run=True`` and return a preview payload including the required
    confirmation token, risk level, and reversibility flag.

System placement:
    Consumed by the ``remediation`` CLI command group and by operator scripts
    that need to inspect what a remediation action would do before committing.
    Actual execution (if ever permitted) requires explicit confirmation tokens
    and is handled by ``src.proxy_guard.remediation``.

Key invariants:
    No function in this package modifies Windows state.  Every preview function
    returns a dict; none raises exceptions for unsupported platforms.

Side effects:
    None at the package level.  Individual preview modules may perform
    lightweight metadata lookups against ``src.proxy_guard.remediation``
    (read-only).
"""

from .dns_flush import preview_dns_flush
from .proxy_disable import preview_proxy_disable
from .rollback import preview_rollback
from .stop_listener import preview_stop_listener
from .stop_reverter import preview_stop_reverter

__all__ = [
    "preview_dns_flush",
    "preview_proxy_disable",
    "preview_rollback",
    "preview_stop_listener",
    "preview_stop_reverter",
]
