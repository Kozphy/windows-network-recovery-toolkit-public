"""Document src.domains.cloud.__init__ responsibilities.

Module responsibility:
    Owns domain adapter wiring for evidence normalization and decision workflows without asserting causal certainty beyond available evidence.

System placement:
    Used by CLI, API, or platform services that assemble endpoint evidence and governance outputs.

Key invariants:
    Keeps observations, hypotheses, policy decisions, remediation, and audit records separate.

Side effects:
    Importing this module has no intended runtime side effects beyond defining constants, classes, or functions.
"""

from src.domains.cloud.adapter import CloudAdapter

__all__ = ["CloudAdapter"]
