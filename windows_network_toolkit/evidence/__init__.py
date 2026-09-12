"""Evidence models and timeline construction for the Technology Risk platform.

Module responsibility:
    Public surface of the ``evidence`` sub-package.  Exports the typed event/
    bundle models, the ordinal confidence helpers, and the ``TimelineBuilder``
    that assembles deduplicated, chronological evidence timelines from
    heterogeneous collector signals.

System placement:
    Imported by ``windows_network_toolkit.pipeline``, the ERP platform routes,
    and test fixtures.  Sits between raw collector output (proxy, registry,
    TLS-path) and the ``decision`` layer that ranks hypotheses.

Key invariants:
    * ``EvidenceEvent`` fields preserve the original observed value verbatim;
      no interpretation is added at this layer.
    * Confidence scores are ordinal ranks, not calibrated probabilities.
    * Observation ≠ proof; this layer records what was seen, not what caused it.
"""

from .confidence_score import explain_confidence, ordinal_confidence
from .evidence_model import EvidenceBundle, EvidenceEvent
from .timeline_builder import TimelineBuilder

__all__ = [
    "EvidenceBundle",
    "EvidenceEvent",
    "TimelineBuilder",
    "explain_confidence",
    "ordinal_confidence",
]
