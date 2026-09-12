"""Attribution provider protocol and neutral fallback for platform demos.

Module responsibility:
    Define the :class:`AttributionProvider` protocol and :func:`unattributed` placeholder
    used when probes or optional dependencies are unavailable.

System placement:
    Implemented by ``psutil_provider``, ``polling``, and ``windows_eventlog`` under
    ``platform_core/attribution/``; consumed by platform ingest/attribution routes.

Key invariants:
    * Providers must not claim forensic proof without authoritative telemetry sources
      (Sysmon EID 13, Security 4657, trusted Procmon CSV).
    * :func:`unattributed` is the explicit "no signal" row — distinct from low-confidence
      heuristic matches.

Output guarantees:
    :class:`~platform_core.events.ActorAttribution` with ``provider`` string identifying
    the implementation.

Audit Notes:
    Dashboards should display ``method`` and ``notes`` verbatim; do not upgrade
    ``confidence`` in UI layers beyond what the provider emitted.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from platform_core.events import ActorAttribution


@runtime_checkable
class AttributionProvider(Protocol):
    """Pluggable heuristic or evidence-backed attribution implementations."""

    name: str

    def describe(self) -> str:
        """Human-readable capability description for docs / dashboards."""

        ...

    def attribute(self, context: dict[str, Any]) -> ActorAttribution:
        """Return best-effort :class:`~platform_core.events.ActorAttribution` for ``context``."""


def unattributed() -> ActorAttribution:
    """Neutral placeholder when probes are unavailable."""

    return ActorAttribution(
        confidence="none",
        method="none",
        notes=["Attribution unavailable or not requested."],
        provider="noop",
        details={},
    )
