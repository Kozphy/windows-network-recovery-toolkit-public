"""Diagnose-first localhost proxy drift investigation package.

Public API:
    ``run_proxy_investigation`` — read-only evidence collection, hypothesis ranking,
    markdown report, and optional JSONL audit.

Usage:
    ``python -c "from pathlib import Path; from src.proxy_investigation import run_proxy_investigation; ..."``

Safety:
    Does not mutate proxies or kill processes; remediation rows are preview-only.

See also:
    ``docs/proxy_investigation_workflow.md`` when present; ``src.proxy_guard`` for live remediation CLIs.
"""

from src.proxy_investigation.workflow import run_proxy_investigation

__all__ = ["run_proxy_investigation"]
