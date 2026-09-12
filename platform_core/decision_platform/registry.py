"""Registry of domain adapters.

System placement:
    - Public lookup for HTTP handlers, CLIs, and tests.
    - Singleton adapter instances are created at import time.

Usage::

    from platform_core.decision_platform import AdapterContext, PlatformDomain, get_adapter

    result = get_adapter(PlatformDomain.WINDOWS).evaluate(AdapterContext(payload={...}))
"""

from __future__ import annotations

from .adapter import DomainAdapter
from .adapters import (
    CloudAdapter,
    InfrastructureAdapter,
    MarketAdapter,
    SecurityAdapter,
    WindowsAdapter,
)
from .models import PlatformDomain

_ADAPTERS: dict[PlatformDomain, DomainAdapter] = {
    PlatformDomain.WINDOWS: WindowsAdapter(),
    PlatformDomain.SECURITY: SecurityAdapter(),
    PlatformDomain.CLOUD: CloudAdapter(),
    PlatformDomain.INFRASTRUCTURE: InfrastructureAdapter(),
    PlatformDomain.MARKET_EVENTS: MarketAdapter(),
}


def get_adapter(domain: PlatformDomain | str) -> DomainAdapter:
    """Resolve a registered domain adapter.

    Args:
        domain: :class:`PlatformDomain` member or string value (e.g. ``"windows"``).

    Returns:
        Singleton adapter instance for the domain.

    Raises:
        KeyError: When ``domain`` is not registered.
    """
    key = PlatformDomain(domain) if isinstance(domain, str) else domain
    try:
        return _ADAPTERS[key]
    except KeyError as exc:
        raise KeyError(f"unknown platform domain: {domain}") from exc


def list_domains() -> list[str]:
    """List registered domain string values in sorted order.

    Returns:
        Sorted list of :class:`PlatformDomain` values (e.g. ``["cloud", "infrastructure", ...]``).
    """
    return sorted(d.value for d in _ADAPTERS)
