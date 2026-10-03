"""Typed evidence and attribution models for endpoint proxy investigation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

EvidenceStrength = Literal["weak", "medium", "strong", "proof"]


class AttributionLevel(StrEnum):
    """Epistemic ladder from observation to proven registry writer."""

    NONE = "NONE"
    CANDIDATE = "CANDIDATE"
    CORRELATED = "CORRELATED"
    STRONG_CORRELATION = "STRONG_CORRELATION"
    PROVEN_REGISTRY_WRITER = "PROVEN_REGISTRY_WRITER"


@dataclass(frozen=True)
class InvestigationEvidenceItem:
    """Single typed evidence row for audit-friendly reports."""

    evidence_type: str
    source: str
    strength: EvidenceStrength
    description: str
    timestamp_utc: str
    limitations: tuple[str, ...] = ()
    detail: dict[str, Any] = field(default_factory=dict)

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
            "evidence_type": self.evidence_type,
            "source": self.source,
            "strength": self.strength,
            "description": self.description,
            "timestamp_utc": self.timestamp_utc,
            "limitations": list(self.limitations),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ProcessSnapshotRecord:
    """Enriched process row captured at proxy drift or investigation time."""

    pid: int | None
    process_name: str | None
    executable_path: str | None
    command_line: str | None
    parent_pid: int | None
    parent_process_name: str | None
    parent_command_line: str | None
    creation_time_utc: str | None
    sha256: str | None
    path_status: Literal["resolved", "unresolved_path"]
    listening_tcp_ports: tuple[int, ...]
    matched_localhost_port: int | None

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
            "pid": self.pid,
            "process_name": self.process_name,
            "executable_path": self.executable_path,
            "command_line": self.command_line,
            "parent_pid": self.parent_pid,
            "parent_process_name": self.parent_process_name,
            "parent_command_line": self.parent_command_line,
            "creation_time_utc": self.creation_time_utc,
            "sha256": self.sha256,
            "path_status": self.path_status,
            "listening_tcp_ports": list(self.listening_tcp_ports),
            "matched_localhost_port": self.matched_localhost_port,
        }


@dataclass(frozen=True)
class AttributionConclusion:
    """Structured attribution output replacing informal 'likely process' labels."""

    level: AttributionLevel
    suspect_process: str | None
    suspect_pid: int | None
    parent_chain: tuple[str, ...]
    evidence_items: tuple[InvestigationEvidenceItem, ...]
    limitations: tuple[str, ...]
    conclusion_text: str

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
            "level": self.level.value,
            "suspect_process": self.suspect_process,
            "suspect_pid": self.suspect_pid,
            "parent_chain": list(self.parent_chain),
            "evidence": [item.to_jsonable() for item in self.evidence_items],
            "limitations": list(self.limitations),
            "conclusion_text": self.conclusion_text,
        }
