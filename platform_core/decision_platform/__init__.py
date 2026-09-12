"""Multi-domain Decision Intelligence Platform.

.. deprecated::
    Use :mod:`src.platform` as the canonical pipeline. This package remains for
    backward compatibility; new code must not import from here.

Normalizes Windows, Security, Cloud, Infrastructure, and Market Events inputs
into a single pipeline (Observation → Evidence → Decision) backed by
:mod:`src.decision_engine`.

Quick start::

    from platform_core.decision_platform import AdapterContext, PlatformDomain, get_adapter

    result = get_adapter(PlatformDomain.WINDOWS).evaluate(AdapterContext(payload={"proxy_enabled": True}))

See :mod:`platform_core.decision_platform.adapter` for the extension interface and
``docs/decision_platform_architecture.md`` for system diagrams.
"""

from .adapter import AdapterContext, DomainAdapter
from .models import (
    Decision,
    DomainPipelineResult,
    Evidence,
    Observation,
    Outcome,
    PlatformDomain,
)
from .reasoning import run_shared_reasoning
from .registry import get_adapter, list_domains

__all__ = [
    "AdapterContext",
    "Decision",
    "DomainAdapter",
    "DomainPipelineResult",
    "Evidence",
    "Observation",
    "Outcome",
    "PlatformDomain",
    "get_adapter",
    "list_domains",
    "run_shared_reasoning",
]
