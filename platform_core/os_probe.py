"""Cross-platform OS detection and read-only network observations (Linux + WSL + Windows).



Thin compatibility layer over :mod:`platform_core.network_diagnostics`.

"""



from __future__ import annotations

from typing import Any

from platform_core.network_diagnostics import (
    detect_linux_distro,
    detect_os_family,
    get_network_diagnostics,
    is_wsl,
)
from platform_core.network_diagnostics.base import ping_host

__all__ = [

    "collect_linux_network_observations",

    "collect_platform_observations",

    "detect_linux_distro",

    "detect_os_family",

    "is_wsl",

    "ping_host",

]





def collect_linux_network_observations() -> list[dict[str, Any]]:

    """Read-only Linux/WSL network facts suitable for correlation fixtures."""

    provider = get_network_diagnostics()

    if provider.os_family() != "linux":

        return [{"signal_name": "os_family", "value": provider.os_family(), "source": "os_probe"}]

    return provider.collect_observations()





def collect_platform_observations() -> dict[str, Any]:

    """Unified probe entry for API and agents."""

    return get_network_diagnostics().platform_payload()

