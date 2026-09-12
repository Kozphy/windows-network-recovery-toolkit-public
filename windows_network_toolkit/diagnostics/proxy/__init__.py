"""Windows proxy diagnostics — read-only attribution, proof, and timeline.

Module responsibility:
    Export the five proxy diagnostic runner functions consumed by the CLI and
    the evidence sub-package.  Covers WinINET/WinHTTP attribution, dead-proxy
    proof, incident timeline construction, and full incident report assembly.

System placement:
    Imported by ``python -m windows_network_toolkit proxy-status``,
    ``proxy-diagnose``, ``proxy-proof``, ``proxy-timeline``, and
    ``proxy-report`` CLI commands.  Also consumed by
    ``diagnostics/evidence/runner.py`` as part of the full evidence package.

Key invariants:
    * All runners are read-only by default; ``dry_run=True`` is always passed
      to governance envelopes.
    * Remediation output from ``run_proxy_timeline`` / ``run_full_incident_report``
      is preview-only; no proxy mutation occurs in this sub-package.
    * Observation ≠ proof; no function in this module labels a process as
      malicious or confirms an attack.

Side effects:
    None at import time.  Individual runners append to audit JSONL and may
    spawn subprocesses for WinHTTP/registry reads.

Failure modes:
    Import errors from ``proxy/runner.py`` propagate as ``ImportError``.
"""

from windows_network_toolkit.diagnostics.proxy.runner import (
    run_full_incident_report,
    run_proxy_attribution,
    run_proxy_proof,
    run_proxy_status,
    run_proxy_timeline,
)

__all__ = [
    "run_full_incident_report",
    "run_proxy_attribution",
    "run_proxy_proof",
    "run_proxy_status",
    "run_proxy_timeline",
]
