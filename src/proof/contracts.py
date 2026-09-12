"""Shared immutable types for causal verification (Proof Engine).

Module responsibility:
    Provide ``ProofResult`` / ``ProofObservation`` envelopes produced by localhost-proxy HTTPS contrast checks
    and future observe-only probes that attach to diagnose-live artefacts.

Inputs / schemas:
    ``ProofResult`` serializes deterministically via ``to_dict`` for JSON embedding under ``proof_engine``.
    Observation ``outcome`` literals declare pass/fail/skip/error without implying OS-level remediation.

Timezone:
    Consumers stamp wall times elsewhere; structs here carry textual ``detail`` fields only—no clock assumptions.

Duplicates / malformed data:
    Hydration helpers (see ``src.audit.replay``) coerce unknown enums to conservative defaults rather than crashing
    parsers.

Safety / side effects:
    Implementations invoking these types may spawn subprocesses (curl, netsh/netstat/registry reads) documented in
    their modules but **never mutate** HKCU/HKLM firewall or routing tables from Proof Engine constructors defined here.

Audit Notes:
    Review ``ProofObservation`` sequence ordering when diagnosing inconclusive contrasts—skipped steps imply missing
    tooling or permissions rather than benign success.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

OutcomeLiteral = Literal["pass", "fail", "skipped", "error"]


class ProofStatus(StrEnum):
    """Result of causal verification."""

    CONFIRMED = "confirmed"
    """Observed predicted contrast: failure through proxy path, success bypassing it."""

    REJECTED = "rejected"
    """No supporting contrast — e.g. both paths succeed."""

    INCONCLUSIVE = "inconclusive"
    """Cannot determine (missing tools, ambiguous config, both paths fail, etc.)."""


@dataclass(frozen=True)
class ProofObservation:
    """One verification sub-step."""

    step_id: str
    label: str
    outcome: OutcomeLiteral
    detail: str

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
            "step_id": self.step_id,
            "label": self.label,
            "outcome": self.outcome,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ProofResult:
    """Machine- and human-consumable output of one proof."""

    proof_id: str
    status: ProofStatus
    hypothesis: str
    summary: str
    observations: tuple[ProofObservation, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialize for audit / CLI."""
        return {
            "proof_id": self.proof_id,
            "status": self.status.value,
            "hypothesis": self.hypothesis,
            "summary": self.summary,
            "observations": [o.to_dict() for o in self.observations],
            "evidence": dict(self.evidence),
        }


class ProofCheck(ABC):
    """Interface for hypotheses backed by deterministic, reversible probes."""

    @property
    @abstractmethod
    def proof_id(self) -> str:
        """Stable id e.g. ``localhost_proxy_https_contrast``."""

    @property
    @abstractmethod
    def hypothesis_description(self) -> str:
        """Plain-language causal claim being tested."""

    @abstractmethod
    def execute(self, **kwargs: Any) -> ProofResult:
        """Run probes and return structured :class:`ProofResult`.

        Implementations MUST NOT apply destructive or registry-mutating fixes.
        kwargs allow dependency injection for tests (`subprocess_run`, timeouts, …).
        """
