"""Localhost web-app diagnostics — ERR_CONNECTION_REFUSED / refused-to-connect evidence.

Module responsibility:
    Export the primary diagnose and watch entry points consumed by the
    Windows Network Toolkit CLI for investigating ``ERR_CONNECTION_REFUSED``
    on loopback (``localhost`` / ``127.0.0.1`` / ``::1``) web apps.  The
    package orchestrates TCP probing, listener discovery, HTTP comparison,
    proxy-evidence collection, classification, and preview remediation — all
    without mutating system state.

System placement:
    Invoked by the CLI commands:
        ``python -m windows_network_toolkit localhost-diagnose``
        ``python -m windows_network_toolkit localhost-watch``
    Also importable by tests via fixture injection (``inject=…``).

Key invariants:
    * Read-only by default; no registry, firewall, or service mutations.
    * Remediation output is PREVIEW-only and requires separate confirmation.
    * Observation ≠ proof; CONNECTION_REFUSED ≠ firewall block.
    * All reports carry ``limitations[]`` to discourage overconfident conclusions.

Side effects:
    Importing this package does not touch the OS.  ``run_localhost_diagnose``
    soft-appends to ``.audit/localhost-diagnose.jsonl`` on success.

Failure modes:
    ``TargetValidationError`` is raised for malformed or non-loopback targets.
    Subprocess failures (``netstat``, ``powershell``) are soft-recorded in
    ``collection_errors`` and do not abort the run.
"""

from .formatters import format_localhost_diagnose_human
from .runner import render_localhost_diagnose, run_localhost_diagnose
from .target import TargetValidationError, parse_localhost_target
from .watch import run_localhost_watch

__all__ = [
    "TargetValidationError",
    "format_localhost_diagnose_human",
    "parse_localhost_target",
    "render_localhost_diagnose",
    "run_localhost_diagnose",
    "run_localhost_watch",
]
