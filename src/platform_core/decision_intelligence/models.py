"""Decision Intelligence Platform — federated multi-domain models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.platform_core import SCHEMA_VERSION
from src.platform_core.contracts import EvidenceBundle, EvidenceTierName

PolicyPosture = Literal["ALLOW", "PREVIEW", "OBSERVE", "DEFER", "BLOCK"]


class DecisionDomain(StrEnum):
    """Represent the decision domain enum.

    Variants:
        IT_OPERATIONS: Structured value carried by this enum.
        SECURITY: Structured value carried by this enum.
        RISK: Structured value carried by this enum.
        BUSINESS: Structured value carried by this enum.
        COMPLIANCE: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    IT_OPERATIONS = "it_operations"
    SECURITY = "security"
    RISK = "risk"
    BUSINESS = "business"
    COMPLIANCE = "compliance"


class EvidenceTrace(BaseModel):
    """Represent the evidence trace type.

    Key fields:
        evidence_id: Structured value carried by this type.
        signal: Structured value carried by this type.
        tier: Structured value carried by this type.
        weight: Structured value carried by this type.
        role: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    evidence_id: str
    signal: str = ""
    tier: EvidenceTierName = "OBSERVED_ONLY"
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    role: Literal["supporting", "contradicting", "missing"] = "supporting"


class ScoreExplain(BaseModel):
    """Represent the score explain type.

    Key fields:
        benefit: Structured value carried by this type.
        risk: Structured value carried by this type.
        confidence: Structured value carried by this type.
        final_score: Structured value carried by this type.
        benefit_components: Structured value carried by this type.
        risk_components: Structured value carried by this type.
        confidence_components: Structured value carried by this type.
        formulas: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    benefit: int = Field(ge=0, le=100)
    risk: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    final_score: int = Field(ge=0, le=100)
    benefit_components: dict[str, float] = Field(default_factory=dict)
    risk_components: dict[str, float] = Field(default_factory=dict)
    confidence_components: dict[str, float] = Field(default_factory=dict)
    formulas: dict[str, str] = Field(default_factory=dict)


class DomainRecommendation(BaseModel):
    """Represent the domain recommendation type.

    Key fields:
        domain: Structured value carried by this type.
        recommendation_id: Structured value carried by this type.
        title: Structured value carried by this type.
        recommendation: Structured value carried by this type.
        policy_posture: Structured value carried by this type.
        confidence: Structured value carried by this type.
        confidence_display: Structured value carried by this type.
        evidence_trace: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    domain: DecisionDomain
    recommendation_id: str
    title: str
    recommendation: str
    policy_posture: PolicyPosture
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_display: str
    evidence_trace: list[EvidenceTrace] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    explain: ScoreExplain
    ranked_alternatives: list[str] = Field(default_factory=list)


class FederatedEvidenceInput(BaseModel):
    """Represent the federated evidence input type.

    Key fields:
        incident_id: Structured value carried by this type.
        bundle: Structured value carried by this type.
        hypothesis_primary: Structured value carried by this type.
        classification: Structured value carried by this type.
        proof_status: Structured value carried by this type.
        limitations: Structured value carried by this type.
        metadata: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    incident_id: str
    bundle: EvidenceBundle
    hypothesis_primary: str | None = None
    classification: str | None = None
    proof_status: str | None = None
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExplainabilityGraph(BaseModel):
    """Represent the explainability graph type.

    Key fields:
        nodes: Structured value carried by this type.
        edges: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    nodes: list[dict[str, str]] = Field(default_factory=list)
    edges: list[dict[str, str]] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """Represent the audit record type.

    Key fields:
        audit_id: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        content_digest: Structured value carried by this type.
        domains_evaluated: Structured value carried by this type.
        policy_postures: Structured value carried by this type.
        replay_anchor: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    audit_id: str
    incident_id: str
    timestamp_utc: str
    content_digest: str
    domains_evaluated: list[str] = Field(default_factory=list)
    policy_postures: dict[str, str] = Field(default_factory=dict)
    replay_anchor: str = ""


class FederatedDecisionResult(BaseModel):
    """Represent the federated decision result type.

    Key fields:
        incident_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        recommendations: Structured value carried by this type.
        explainability: Structured value carried by this type.
        audit: Structured value carried by this type.
        epistemic_notice: Structured value carried by this type.
        metadata: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    incident_id: str
    schema_version: str = SCHEMA_VERSION
    recommendations: list[DomainRecommendation]
    explainability: ExplainabilityGraph
    audit: AuditRecord
    epistemic_notice: str = (
        "Domain recommendations are advisory; execution requires policy gates and human approval."
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return self.model_dump()
