"""Read-only diagnostic runners for Windows endpoint reliability.

Module responsibility:
    Top-level namespace for all diagnostic sub-packages: localhost web-app
    diagnostics (ERR_CONNECTION_REFUSED), proxy attribution, and endpoint
    network evidence assessment.  Every runner in this tree is read-only by
    default; remediation is preview-only and requires explicit policy gates.

System placement:
    Imported by ``windows_network_toolkit/__init__.py`` and the CLI layer.
    Sub-packages (localhost, proxy, evidence) are also importable directly.

Key invariants:
    * No sub-package modifies Windows state (registry, firewall, services).
    * Observation ≠ proof; all outputs carry ``limitations[]``.
    * Fixture-injection (``inject=…``) is the primary test seam; all runners
      accept it to avoid live OS probes in unit tests.

Side effects:
    None at import time.  Individual runners may soft-append to
    ``.audit/`` JSONL logs and write ``evidence_out`` files.

Failure modes:
    Sub-package import errors surface as normal ``ImportError``; no silent
    swallowing.  Missing optional dependencies are reported, not hidden.
"""
