"""Windows Network Recovery Toolkit — Python diagnostics, proxy guard, and decision CLI surfaces.

Package responsibility:
    Exposes ``SCRIPT_VERSION`` and hosts the layered implementation behind ``python -m src``: collectors under
    ``src.diagnostics``, observe-only proof helpers under ``src.proof``, heuristic + policy pipelines under
    ``src.hypothesis``, ``src.observation``, ``src.policy``, ``src.audit``, and argparse wiring in ``src.cli`` with
    execution bodies in ``src.command_handlers``.

System placement:
    Sits beside ``failure_system/`` (Failure Knowledge System) and optional ``endpoint_agent`` / ``backend`` bridges.
    Batch workflows under ``scripts/`` invoke this package indirectly; importing ``src`` does not execute probes.

Side effects:
    Package import resolves ``src.version`` from disk synchronously once. Actual filesystem or subprocess activity
    happens only inside invoked commands (see submodule docstrings).

See Also:
    Root ``README.md`` decision-pipeline narrative, ``docs/decision_engine_v2.md``, and ``docs/cli_reference.md``.
"""

from .version import SCRIPT_VERSION

__all__ = ["SCRIPT_VERSION"]
