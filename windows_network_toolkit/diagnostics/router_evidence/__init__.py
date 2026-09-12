"""Router evidence import and correlation — public exports.

Module responsibility:
    Re-export ``run_router_import``, ``run_router_correlation``, and ``load_router_jsonl``.

System placement:
    Entry surface for ``router-import`` / ``router-correlate`` CLI and ``lan_privacy.runner``.

Key invariants:
    * Import and normalize only — no router configuration changes.
    * Normalized events carry ``ROUTER_LEVEL_EVIDENCE`` provenance.

Side effects:
    * None at import time beyond submodule loading.
"""

from .runner import run_router_correlation, run_router_import, load_router_jsonl

__all__ = ["run_router_import", "run_router_correlation", "load_router_jsonl"]
