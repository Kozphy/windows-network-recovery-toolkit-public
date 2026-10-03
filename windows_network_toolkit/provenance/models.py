"""Domain provenance data models — evidence, scores, policy outcomes.

Module responsibility:
    Dataclass / enum schemas for the domain-provenance pipeline.

System placement:
    Shared by normalize, collectors, scoring, policy, redact, and pipeline.

Key invariants:
    * ``operator_country`` and ``infrastructure_countries`` are separate fields.
    * ``SCHEMA_VERSION`` tags serialized artifacts.
    * Limitations accompany every user-facing result.

Side effects:
    None — types and constants only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "wnt.domain_provenance.v1"

PROVENANCE_LIMITATIONS = [
    "Operator-country assessment is evidence-backed correlation, not legal ownership proof.",
    "Infrastructure (hosting/CDN/ASN) geography must not be treated as operator country.",
    "RDAP and GeoIP sources may be incomplete, delayed, or privacy-redacted.",
    "Classification is not accusation; provenance never authorizes remediation.",
]


class ConfidenceBand(StrEnum):
    """Ordinal confidence band for operator-country assessment."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INSUFFICIENT = "insufficient"


class PolicyDecision(StrEnum):
    """Policy outcome for provenance assessments.

    Variants:
        ALLOW_WITH_HUMAN_REVIEW: Observation may be used for review only.
        BLOCK_ATTRIBUTION_ENFORCEMENT: Auto-enforcement from provenance blocked.
        DENY_REMEDIATION: Provenance must not drive remediation apply.
    """

    ALLOW_WITH_HUMAN_REVIEW = "ALLOW_WITH_HUMAN_REVIEW"
    BLOCK_ATTRIBUTION_ENFORCEMENT = "BLOCK_ATTRIBUTION_ENFORCEMENT"
    DENY_REMEDIATION = "DENY_REMEDIATION"


class SignalKind(StrEnum):
    """Whether a signal informs operator country or infrastructure only."""

    OPERATOR = "operator"
    INFRASTRUCTURE = "infrastructure"
    CONTEXT = "context"


@dataclass(frozen=True)
class ProvenanceSignal:
    """One evidence signal contributing to provenance assessment.

    Attributes:
        id: Stable signal identifier (e.g. ``cctld``, ``rdap_registrant_country``).
        kind: Operator vs infrastructure vs context.
        country: ISO 3166-1 alpha-2 when known, else empty.
        weight: Non-negative weight used only for operator signals in scoring.
        source: Collector / adapter name.
        detail: Short human-readable observation.
        observed: Raw observed value (may be redacted later).
    """

    id: str
    kind: SignalKind
    country: str = ""
    weight: float = 0.0
    source: str = ""
    detail: str = ""
    observed: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize signal to a JSON-friendly dict."""
        return {
            "id": self.id,
            "kind": self.kind.value,
            "country": self.country,
            "weight": self.weight,
            "source": self.source,
            "detail": self.detail,
            "observed": self.observed,
        }


@dataclass
class InfrastructureMismatch:
    """Informational mismatch between operator and hosting geography."""

    operator_country: str
    infrastructure_countries: list[str]
    severity: str = "informational"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize mismatch note."""
        return asdict(self)


@dataclass
class ProvenanceScore:
    """Scored operator-country hypothesis."""

    operator_country: str
    confidence: float
    confidence_band: ConfidenceBand
    support_by_country: dict[str, float] = field(default_factory=dict)
    infrastructure_countries: list[str] = field(default_factory=list)
    mismatches: list[InfrastructureMismatch] = field(default_factory=list)
    signals: list[ProvenanceSignal] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize score payload."""
        return {
            "operator_country": self.operator_country,
            "confidence": self.confidence,
            "confidence_band": self.confidence_band.value,
            "support_by_country": dict(self.support_by_country),
            "infrastructure_countries": list(self.infrastructure_countries),
            "mismatches": [m.to_dict() for m in self.mismatches],
            "signals": [s.to_dict() for s in self.signals],
        }


@dataclass
class ProvenancePolicy:
    """Policy gate for provenance — always human-review, never remediation."""

    decision: PolicyDecision
    human_review_required: bool
    attribution_enforcement_allowed: bool
    remediation_allowed: bool
    blocked_actions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy gate."""
        return {
            "decision": self.decision.value,
            "human_review_required": self.human_review_required,
            "attribution_enforcement_allowed": self.attribution_enforcement_allowed,
            "remediation_allowed": self.remediation_allowed,
            "blocked_actions": list(self.blocked_actions),
            "notes": list(self.notes),
        }


@dataclass
class DomainProvenanceResult:
    """Full domain-provenance assessment envelope."""

    schema_version: str
    assessment_id: str
    timestamp_utc: str
    target_raw: str
    target_normalized: str
    mode: str
    score: ProvenanceScore
    policy: ProvenancePolicy
    limitations: list[str] = field(default_factory=list)
    audit_appended: bool | None = None
    audit_error: str | None = None
    redaction: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize full result for CLI / audit."""
        return {
            "schema_version": self.schema_version,
            "assessment_id": self.assessment_id,
            "timestamp_utc": self.timestamp_utc,
            "target_raw": self.target_raw,
            "target_normalized": self.target_normalized,
            "mode": self.mode,
            "operator_country": self.score.operator_country,
            "confidence": self.score.confidence,
            "confidence_band": self.score.confidence_band.value,
            "score": self.score.to_dict(),
            "policy": self.policy.to_dict(),
            "limitations": list(self.limitations),
            "audit_appended": self.audit_appended,
            "audit_error": self.audit_error,
            "redaction": dict(self.redaction),
        }
