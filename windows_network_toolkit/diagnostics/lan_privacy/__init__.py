"""LAN Privacy & Device Discovery Monitor — public pipeline exports.

Module responsibility:
    Re-export collectors, watch, and report/risk pipelines for the LAN privacy CLI.

System placement:
    Entry surface for ``windows_network_toolkit.cli`` ``lan-*`` commands and tests.

Key invariants:
    * Pipelines remain read-only at the observability layer; no auto-remediation here.
    * ``__all__`` lists the supported public callables only.

Side effects:
    * None at import time beyond submodule loading.
"""

from .collectors import collect_inventory, collect_mdns_summary, collect_ssdp_summary
from .runner import (
    run_executive_report_pipeline,
    run_lan_privacy_report_pipeline,
    run_lan_risk_score_pipeline,
)
from .watch import run_lan_watch

__all__ = [
    "collect_inventory",
    "collect_mdns_summary",
    "collect_ssdp_summary",
    "run_lan_watch",
    "run_lan_risk_score_pipeline",
    "run_lan_privacy_report_pipeline",
    "run_executive_report_pipeline",
]
