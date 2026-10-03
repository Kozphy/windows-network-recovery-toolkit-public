"""Evidence pipeline for offline-friendly proxy/registry attribution.

Module responsibility:
    Re-exports attribution types and :func:`~evidence.attribution_engine.build_attribution` so callers
    (for example ``backend.platform_routes``) import a stable surface without wiring every submodule.

System placement:
    Sits beside ``src.proxy_guard`` (live Windows polling) and ``platform_core`` (JSONL platform).
    **Does not** read the live registry or start ETW sessions; ingest dicts/CSV excerpts only.

Key invariants:
    * Outputs label ``attribution_level`` honestly: polling-only paths stay ``heuristic`` unless
      Sysmon/Procmon/ETW-shaped inputs justify stronger tiers.
    * No subprocess repair, firewall, or adapter mutation from this package.

Engineering Notes:
    Kept stdlib-heavy on purpose—pytest and air-gapped demos import without Win32 extensions.

Examples:
    Typical usage resolves through ``platform_core.storage.append_attribution_context`` plus HTTP
    ``GET /platform/attribution/{event_id}``, not via direct imports in beginner scripts.

Note:
    ``__all__`` enumerates symbols stable for ``from evidence import …`` re-exports.
"""

from evidence.attribution_engine import build_attribution
from evidence.evidence_event import EvidenceEvent
from evidence.models import (
    AttributionLevel,
    AttributionResult,
    EvidenceItem,
    coerce_attribution_level,
)

__all__ = [
    "AttributionLevel",
    "AttributionResult",
    "EvidenceEvent",
    "EvidenceItem",
    "build_attribution",
    "coerce_attribution_level",
]
