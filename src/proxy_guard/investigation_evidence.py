"""Structured evidence tiers for read-only proxy investigation bundles.

Separates observed facts, correlated inference, and explicit non-proof boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

ProofStatus = Literal[
    "OBSERVED_ONLY",
    "CORRELATED",
    "STRONGLY_CORRELATED",
    "PROVEN_BY_EVENT_LOG",
    "PROVEN_BY_SYSMON",
    "PROVEN_BY_PROCMON",
    "PROVEN_BY_ETW",
    "UNKNOWN",
]

EvidenceTier = Literal["OBSERVED", "CORRELATED", "NOT_PROVEN"]


class ProofStatusEnum(StrEnum):
    """Machine-readable proof status; never emit PROVEN_* without event evidence."""

    OBSERVED_ONLY = "OBSERVED_ONLY"
    CORRELATED = "CORRELATED"
    STRONGLY_CORRELATED = "STRONGLY_CORRELATED"
    PROVEN_BY_EVENT_LOG = "PROVEN_BY_EVENT_LOG"
    PROVEN_BY_SYSMON = "PROVEN_BY_SYSMON"
    PROVEN_BY_PROCMON = "PROVEN_BY_PROCMON"
    PROVEN_BY_ETW = "PROVEN_BY_ETW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceLine:
    """Single evidence statement with explicit epistemic tier."""

    tier: EvidenceTier
    text: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InvestigationEvidence:
    """Aggregated evidence model for proxy investigation output."""

    observed_signals: tuple[str, ...]
    correlated_signals: tuple[str, ...]
    contradicting_signals: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    suspected_process: dict[str, Any] | None
    listener_evidence: dict[str, Any]
    registry_evidence: dict[str, Any]
    command_line_evidence: dict[str, Any]
    parent_process_evidence: dict[str, Any]
    startup_evidence: dict[str, Any]
    proof_status: ProofStatus
    confidence: float
    limitations: tuple[str, ...]
    lines: tuple[EvidenceLine, ...]

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "observed_signals": list(self.observed_signals),
            "correlated_signals": list(self.correlated_signals),
            "contradicting_signals": list(self.contradicting_signals),
            "missing_evidence": list(self.missing_evidence),
            "suspected_process": self.suspected_process,
            "listener_evidence": self.listener_evidence,
            "registry_evidence": self.registry_evidence,
            "command_line_evidence": self.command_line_evidence,
            "parent_process_evidence": self.parent_process_evidence,
            "startup_evidence": self.startup_evidence,
            "proof_status": self.proof_status,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
            "lines": [
                {"tier": line.tier, "text": line.text, "detail": line.detail}
                for line in self.lines
            ],
        }
