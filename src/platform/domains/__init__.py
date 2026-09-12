"""Document src.platform.domains.__init__ responsibilities.

Module responsibility:
    Owns platform orchestration models, adapters, or compatibility helpers without asserting causal certainty beyond available evidence.

System placement:
    Used by CLI, API, or platform services that assemble endpoint evidence and governance outputs.

Key invariants:
    Keeps observations, hypotheses, policy decisions, remediation, and audit records separate.

Side effects:
    Importing this module has no intended runtime side effects beyond defining constants, classes, or functions.
"""

from src.platform.domains.cloud import CloudAdapter
from src.platform.domains.infrastructure import InfrastructureAdapter
from src.platform.domains.market import MarketAdapter
from src.platform.domains.security import SecurityAdapter
from src.platform.domains.windows import WindowsAdapter

__all__ = [
    "CloudAdapter",
    "InfrastructureAdapter",
    "MarketAdapter",
    "SecurityAdapter",
    "WindowsAdapter",
]
