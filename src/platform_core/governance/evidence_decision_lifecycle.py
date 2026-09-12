"""First-class evidence-to-decision lifecycle artifacts.

This module formalizes the conceptual chain:
Observation -> Claim -> Evidence -> Verification -> Uncertainty -> Knowledge -> Decision.

It is intentionally additive: existing RiskDecisionRecord behavior remains unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ClaimStatus(StrEnum):
    """Represent the claim status enum.

    Variants:
        PROPOSED: Structured value carried by this enum.
        SUPPORTED: Structured value carried by this enum.
        PARTIALLY_SUPPORTED: Structured value carried by this enum.
        NOT_SUPPORTED: Structured value carried by this enum.
        INCONCLUSIVE: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    NOT_SUPPORTED = "not_supported"
    INCONCLUSIVE = "inconclusive"


class VerificationStatus(StrEnum):
    """Represent the verification status enum.

    Variants:
        VERIFIED: Structured value carried by this enum.
        PARTIALLY_VERIFIED: Structured value carried by this enum.
        NOT_VERIFIED: Structured value carried by this enum.
        INCONCLUSIVE: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    NOT_VERIFIED = "not_verified"
    INCONCLUSIVE = "inconclusive"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Claim(BaseModel):
    """A falsifiable statement derived from one or more observations."""

    schema_version: str = "claim.v1"
    claim_id: str
    incident_id: str
    statement: str
    claim_type: str = "diagnostic"
    source_observations: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    status: ClaimStatus = ClaimStatus.PROPOSED
    created_at: str = Field(default_factory=_utc_now)


class VerificationResult(BaseModel):
    """Result of testing whether evidence actually supports a claim."""

    schema_version: str = "verification_result.v1"
    claim_id: str
    status: VerificationStatus
    checks_run: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    reproducible: bool = False
    verifier: str = "deterministic_platform"
    verified_at: str = Field(default_factory=_utc_now)


class UncertaintyAssessment(BaseModel):
    """Explicit uncertainty artifact; confidence is not treated as probability."""

    schema_version: str = "uncertainty_assessment.v1"
    claim_id: str
    confidence_ordinal: str = "medium"
    confidence_score: float | None = Field(default=None, ge=0.0, le=1.0)
    probability_calibrated: bool = False
    uncertainty_sources: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    alternative_hypotheses: list[str] = Field(default_factory=list)


class KnowledgeRecord(BaseModel):
    """A verified, bounded statement suitable for downstream decision-making."""

    schema_version: str = "knowledge_record.v1"
    knowledge_id: str
    incident_id: str
    claim_id: str
    statement: str
    verification_status: VerificationStatus
    uncertainty: UncertaintyAssessment
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    valid_for_decision: bool = False
    derived_at: str = Field(default_factory=_utc_now)


class EvidenceDecisionLifecycle(BaseModel):
    """Envelope linking knowledge artifacts to an existing risk decision."""

    schema_version: str = "evidence_decision_lifecycle.v1"
    incident_id: str
    claim: Claim
    verification: VerificationResult
    uncertainty: UncertaintyAssessment
    knowledge: KnowledgeRecord
    decision_id: str = ""
    outcome: dict[str, Any] = Field(default_factory=dict)
    feedback: list[dict[str, Any]] = Field(default_factory=list)


def lifecycle_from_risk_decision(record: Any) -> EvidenceDecisionLifecycle:
    """Adapt an existing RiskDecisionRecord into the explicit lifecycle.

    The adapter does not invent calibrated probability. It preserves the existing
    ordinal confidence and limitations and marks verification conservatively from
    the available proof tier.
    """

    incident_id = str(record.incident_id)
    claim_id = f"claim-{incident_id}"
    classification = str(record.classification or "UNCLASSIFIED")
    proof_tier = getattr(record.proof_tier, "value", str(record.proof_tier))
    evidence_id = str(record.evidence_id or f"ev-{incident_id}")
    limitations = list(record.limitations or [])

    proof_rank = 0
    try:
        proof_rank = int(str(proof_tier).split("_")[0].replace("T", ""))
    except (ValueError, IndexError):
        proof_rank = 0

    if proof_rank >= 3:
        verification_status = VerificationStatus.VERIFIED
        claim_status = ClaimStatus.SUPPORTED
    elif proof_rank >= 2:
        verification_status = VerificationStatus.PARTIALLY_VERIFIED
        claim_status = ClaimStatus.PARTIALLY_SUPPORTED
    else:
        verification_status = VerificationStatus.INCONCLUSIVE
        claim_status = ClaimStatus.INCONCLUSIVE

    uncertainty = UncertaintyAssessment(
        claim_id=claim_id,
        confidence_ordinal=str(record.confidence_label),
        confidence_score=float(record.confidence_score),
        probability_calibrated=False,
        uncertainty_sources=limitations,
        missing_evidence=[] if verification_status == VerificationStatus.VERIFIED else [
            "Higher proof-tier corroboration may be required before stronger causal claims."
        ],
    )

    claim = Claim(
        claim_id=claim_id,
        incident_id=incident_id,
        statement=f"Endpoint evidence is consistent with classification {classification}.",
        source_observations=list(record.secondary_signals or []),
        evidence_ids=[evidence_id],
        status=claim_status,
    )

    verification = VerificationResult(
        claim_id=claim_id,
        status=verification_status,
        checks_run=["proof_tier_resolution", "control_testing", "deterministic_classification"],
        supporting_evidence=[evidence_id],
        limitations=limitations,
        reproducible=proof_rank >= 2,
    )

    knowledge = KnowledgeRecord(
        knowledge_id=f"knowledge-{incident_id}",
        incident_id=incident_id,
        claim_id=claim_id,
        statement=(
            f"Verified evidence supports {classification}."
            if verification_status == VerificationStatus.VERIFIED
            else f"Available evidence is consistent with {classification}, subject to stated limitations."
        ),
        verification_status=verification_status,
        uncertainty=uncertainty,
        evidence_ids=[evidence_id],
        limitations=limitations,
        valid_for_decision=verification_status in {
            VerificationStatus.VERIFIED,
            VerificationStatus.PARTIALLY_VERIFIED,
        },
    )

    return EvidenceDecisionLifecycle(
        incident_id=incident_id,
        claim=claim,
        verification=verification,
        uncertainty=uncertainty,
        knowledge=knowledge,
        decision_id=str(record.decision_key or record.audit_id),
    )
