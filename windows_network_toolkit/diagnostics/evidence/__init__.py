"""Endpoint Network Evidence & Risk diagnostics.

Module responsibility:
    Export the two top-level evidence assessment runners used by the CLI and
    integration tests.  Combines proxy attribution, network proof, TLS MITM
    analysis, and website-risk scoring into a single merged evidence package.

System placement:
    Imported by the CLI for ``python -m windows_network_toolkit evidence-assess``
    and ``evidence-report`` commands.  Also consumed by integration tests that
    exercise the full evidence pipeline end-to-end.

Key invariants:
    * Both runners are read-only by default (``dry_run=True`` throughout).
    * ``safety_notes`` in the returned package explicitly state that this is
      preview-only evidence collection, not antivirus or phishing protection.
    * Classification code ``"DEAD_PROXY_CONFIG"`` from the writer-attribution
      step gates the ``dead_localhost_proxy`` signal in the proof engine.

Side effects:
    None at import time.  Individual runners spawn subprocesses and network
    probes when fixture injection is absent.

Failure modes:
    Import errors from ``evidence/runner.py`` propagate as ``ImportError``.
"""

from .runner import run_evidence_assessment, run_evidence_report

__all__ = ["run_evidence_assessment", "run_evidence_report"]
