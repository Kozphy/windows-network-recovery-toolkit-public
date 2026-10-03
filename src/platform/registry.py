"""Document src.platform.registry responsibilities.

Module responsibility:
    Owns platform orchestration models, adapters, or compatibility helpers without asserting causal certainty beyond available evidence.

System placement:
    Used by CLI, API, or platform services that assemble endpoint evidence and governance outputs.

Key invariants:
    Keeps observations, hypotheses, policy decisions, remediation, and audit records separate.

Side effects:
    Importing this module has no intended runtime side effects beyond defining constants, classes, or functions.
"""

from __future__ import annotations

from src.platform.domains.base import DomainAdapter
from src.platform.domains.cloud import CloudAdapter
from src.platform.domains.infrastructure import InfrastructureAdapter
from src.platform.domains.market import MarketAdapter
from src.platform.domains.security import SecurityAdapter
from src.platform.domains.windows import WindowsAdapter

_ADAPTERS: dict[str, DomainAdapter] = {
    "windows": WindowsAdapter(),
    "security": SecurityAdapter(),
    "cloud": CloudAdapter(),
    "infrastructure": InfrastructureAdapter(),
    "market": MarketAdapter(),
}


def get_adapter(domain: str) -> DomainAdapter:
    """Get adapter.

    Args:
        domain: The domain value supplied by the caller.

    Returns:
        The DomainAdapter result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    key = domain.lower().replace("_", "")
    if key == "marketevents":
        key = "market"
    if key not in _ADAPTERS:
        raise KeyError(domain)
    return _ADAPTERS[key]


def all_adapters() -> list[DomainAdapter]:
    """All adapters.

    Args:
        None.

    Returns:
        The list[DomainAdapter] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return list(_ADAPTERS.values())
