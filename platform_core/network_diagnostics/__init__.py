"""Cross-platform network diagnostics: read-only observations, OS-specific providers."""

from __future__ import annotations

from platform_core.network_diagnostics.base import (
    NetworkDiagnosticsProvider,
    detect_linux_distro,
    detect_os_family,
    is_wsl,
)
from platform_core.network_diagnostics.darwin import DarwinNetworkDiagnostics
from platform_core.network_diagnostics.generic import GenericNetworkDiagnostics
from platform_core.network_diagnostics.linux import LinuxNetworkDiagnostics
from platform_core.network_diagnostics.windows import WindowsNetworkDiagnostics


def get_network_diagnostics() -> NetworkDiagnosticsProvider:
    """Return the diagnostics provider for the current host OS."""
    family = detect_os_family()
    if family == "windows":
        return WindowsNetworkDiagnostics()
    if family == "linux":
        return LinuxNetworkDiagnostics()
    if family == "darwin":
        return DarwinNetworkDiagnostics()
    return GenericNetworkDiagnostics()


__all__ = [
    "DarwinNetworkDiagnostics",
    "NetworkDiagnosticsProvider",
    "LinuxNetworkDiagnostics",
    "WindowsNetworkDiagnostics",
    "detect_linux_distro",
    "detect_os_family",
    "get_network_diagnostics",
    "is_wsl",
]
