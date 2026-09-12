"""Read-only local endpoint agent (Phase 2 enterprise hardening).

Module responsibility:
    Public surface of the ``agent`` sub-package.  Exports the four primary
    entry points that callers (CLI, tests) use to drive the read-only
    collection lifecycle: single-shot collection, continuous loop, health
    status, and spool status.

System placement:
    Invoked via ``python -m windows_network_toolkit agent *`` CLI commands.
    Sits between the platform-core evidence collection layer and the
    operator-facing CLI.

Key invariants:
    * All exported functions are read-only; they collect and spool evidence
      but never execute remediation, write to the registry, or mutate network
      state.
    * ``automatic_repair=False`` is enforced on every spool event by
      ``read_only.build_evidence_event``.
    * ``READ_ONLY_POLICY_BOUNDARY`` and ``FORBIDDEN_REMEDIATION_MODULES``
      constants (in ``read_only.py``) are the normative safety contract for
      this agent — they must not be weakened without a policy review.
"""

from windows_network_toolkit.agent.read_only import (
    collect_once,
    get_health_status,
    get_spool_status,
    run_agent_loop,
)

__all__ = [
    "collect_once",
    "get_health_status",
    "get_spool_status",
    "run_agent_loop",
]
