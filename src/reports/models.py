"""Evidence tree models — Step 5."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceNode:
    """Represent evidence node data used by the toolkit.
    
    Attributes:
        id: Field or variant describing id evidence or state.
        parent_id: Field or variant describing parent id evidence or state.
        node_type: Field or variant describing node type evidence or state.
        title: Field or variant describing title evidence or state.
        summary: Field or variant describing summary evidence or state.
        timestamp_utc: Field or variant describing timestamp utc evidence or state.
        source: Field or variant describing source evidence or state.
        confidence: Field or variant describing confidence evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    id: str
    parent_id: str | None
    node_type: str
    title: str
    summary: str = ""
    timestamp_utc: str | None = None
    source: str = ""
    confidence: float = 0.0
    severity: str | None = None
    raw_event_reference: dict[str, Any] | None = None
    children: list[EvidenceNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "node_type": self.node_type,
            "title": self.title,
            "summary": self.summary,
            "timestamp_utc": self.timestamp_utc,
            "source": self.source,
            "confidence": self.confidence,
            "severity": self.severity,
            "raw_event_reference": self.raw_event_reference,
            "children": [c.to_dict() for c in self.children],
            "label": self.title,
            "explanation": self.summary,
        }
