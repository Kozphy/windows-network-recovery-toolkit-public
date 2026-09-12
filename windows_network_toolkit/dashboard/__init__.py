"""Local monitoring dashboard package (NiceGUI, read-only).

Module responsibility:
    Export dashboard config and runtime entrypoints for the optional NiceGUI UI.

System placement:
    ``python -m`` / CLI dashboard commands; requires ``pip install -e ".[dashboard]"``.

Key invariants:
    Read-only observation surface — does not apply remediation.
"""

from windows_network_toolkit.dashboard.app import create_runtime, run_dashboard
from windows_network_toolkit.dashboard.config import DashboardConfig

__all__ = ["DashboardConfig", "create_runtime", "run_dashboard"]
