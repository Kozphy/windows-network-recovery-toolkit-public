"""Bad Gateway / 502 diagnostic module — read-only HTTP path probes.

Module responsibility:
    Export ``run_bad_gateway_diagnose`` for CLI and auto-fix orchestration.

System placement:
    ``windows_network_toolkit bad-gateway-diagnose``; step 2 of auto-fix-chatgpt.

Key invariants:
    * Read-only; ``dry_run=True`` in CLI path (no remediation apply from this module).
    * Classifications are triage labels, not security verdicts.
"""

from .runner import run_bad_gateway_diagnose

__all__ = ["run_bad_gateway_diagnose"]
