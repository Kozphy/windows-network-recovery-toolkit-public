"""Pydantic schemas for AI-assisted risk analysis."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.platform_core.contracts import DestructiveAction, EvidenceBundle, EvidenceItem

AI_SCHEMA_VERSION = "ai_risk_analyst.v1"

ConfidenceLevel = Literal["very_low", "low", "medium", "high"]
RiskLevel = Literal["low", "medium", "high", "critical"]
ReviewStatus = Literal["not_required", "recommended", "required"]

FORBIDDEN_ACTIONS: tuple[str, ...] = tuple(a.value for a in DestructiveAction)


def utc_now_iso() -> str:
    """Return utc now iso.

    Returns:
        The computed `str` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class AnalystEvidenceBundle(BaseModel):
    """Structured evidence accepted by the AI risk analyst."""

    schema_version: str = AI_SCHEMA_VERSION
    incident_id: str
    created_at: str = Field(default_factory=utc_now_iso)
    proxy_status: dict[str, Any] | None = None
    listener_info: dict[str, Any] | None = None
    timeline_events: list[dict[str, Any]] = Field(default_factory=list)
    tls_proof: dict[str, Any] | None = None
    website_risk: dict[str, Any] | None = None
    audit_log_entries: list[dict[str, Any]] = Field(default_factory=list)
    classification: dict[str, Any] | None = None
    proof: dict[str, Any] | None = None
    policy_decision: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)

    def to_pipeline_bundle(self) -> EvidenceBundle:
        """Map analyst input into canonical pipeline EvidenceBundle items."""
        items: list[EvidenceItem] = []
        if self.proxy_status:
            items.append(
                EvidenceItem(
                    evidence_id=f"ev-proxy-{self.incident_id}",
                    event_id=self.incident_id,
                    timestamp_utc=self.created_at,
                    source="proxy-status",
                    signal="wininet_proxy_state",
                    observed_value=str(self.proxy_status.get("classification", "")),
                    tier="OBSERVED_ONLY",
                    confidence=float(
                        (self.classification or {}).get("confidence", 0.5)
                    ),
                    raw_data=self.proxy_status,
                )
            )
        if self.listener_info:
            items.append(
                EvidenceItem(
                    evidence_id=f"ev-listener-{self.incident_id}",
                    event_id=self.incident_id,
                    timestamp_utc=self.created_at,
                    source="proxy-owner",
                    signal="localhost_listener",
                    observed_value=str(self.listener_info.get("listener_found", "")),
                    tier="OBSERVED_ONLY",
                    raw_data=self.listener_info,
                )
            )
        if self.tls_proof:
            items.append(
                EvidenceItem(
                    evidence_id=f"ev-tls-{self.incident_id}",
                    event_id=self.incident_id,
                    timestamp_utc=self.created_at,
                    source="tls-proof",
                    signal="tls_certificate_contrast",
                    tier="CORRELATED",
                    raw_data=self.tls_proof,
                )
            )
        for idx, event in enumerate(self.timeline_events):
            items.append(
                EvidenceItem(
                    evidence_id=f"ev-tl-{idx}",
                    event_id=self.incident_id,
                    timestamp_utc=str(event.get("timestamp_utc", self.created_at)),
                    source=str(event.get("source", "timeline")),
                    signal=str(event.get("event", "timeline_event")),
                    observed_value=str(event.get("detail", "")),
                    raw_data=event,
                )
            )
        primary = (self.classification or {}).get("primary_classification", "")
        return EvidenceBundle(
            bundle_id=f"bundle-{self.incident_id}",
            incident_id=self.incident_id,
            created_at=self.created_at,
            items=items,
            summary=str(primary),
            tags=self.tags,
        )


# Alias for documentation parity with task spec.
EvidenceBundleInput = AnalystEvidenceBundle


class RiskHypothesis(BaseModel):
    """Represent the risk hypothesis type.

    Key fields:
        hypothesis_id: Structured value carried by this type.
        title: Structured value carried by this type.
        explanation: Structured value carried by this type.
        confidence: Structured value carried by this type.
        supporting_evidence: Structured value carried by this type.
        missing_evidence: Structured value carried by this type.
        alternative_explanations: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    hypothesis_id: str
    title: str
    explanation: str
    confidence: ConfidenceLevel = "medium"
    supporting_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    alternative_explanations: list[str] = Field(default_factory=list)


class HumanReviewRequired(BaseModel):
    """Represent the human review required type.

    Key fields:
        required: Structured value carried by this type.
        status: Structured value carried by this type.
        reasons: Structured value carried by this type.
        checklist: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    required: bool = False
    status: ReviewStatus = "not_required"
    reasons: list[str] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)


class AIRecommendation(BaseModel):
    """Represent the airecommendation type.

    Key fields:
        schema_version: Structured value carried by this type.
        audit_id: Structured value carried by this type.
        provider: Structured value carried by this type.
        incident_summary: Structured value carried by this type.
        likely_hypothesis: Structured value carried by this type.
        missing_evidence: Structured value carried by this type.
        risk_level: Structured value carried by this type.
        confidence_level: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    schema_version: str = AI_SCHEMA_VERSION
    audit_id: str = Field(default_factory=lambda: f"ai-audit-{uuid.uuid4().hex[:12]}")
    provider: str = "local_rule_based"
    incident_summary: str = ""
    likely_hypothesis: str = ""
    missing_evidence: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = "medium"
    confidence_level: ConfidenceLevel = "medium"
    recommended_action: str = ""
    human_review_notes: str = ""
    evidence_used: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    uncertainty: str = ""
    alternative_explanations: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=lambda: list(FORBIDDEN_ACTIONS))
    human_review: HumanReviewRequired = Field(default_factory=HumanReviewRequired)
    hypotheses: list[RiskHypothesis] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    governance_notes: list[str] = Field(default_factory=list)


class DecisionRecord(BaseModel):
    """Represent the decision record type.

    Key fields:
        decision_id: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        recommendation: Structured value carried by this type.
        policy_outcome: Structured value carried by this type.
        executed: Structured value carried by this type.
        operator_id: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    decision_id: str = Field(default_factory=lambda: f"dec-{uuid.uuid4().hex[:12]}")
    incident_id: str
    schema_version: str = AI_SCHEMA_VERSION
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    recommendation: AIRecommendation
    policy_outcome: str = "PREVIEW_ONLY"
    executed: bool = False
    operator_id: str = "unassigned"
    notes: str = ""


class AnalystAuditEntry(BaseModel):
    """AI reasoning metadata appended to audit trails."""

    audit_id: str
    schema_version: str = AI_SCHEMA_VERSION
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    action_type: Literal["ai_analysis_completed", "ai_recommendation_previewed"] = (
        "ai_analysis_completed"
    )
    incident_id: str
    provider: str
    evidence_used: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    uncertainty: str = ""
    recommended_action: str = ""
    forbidden_actions: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = "medium"
    confidence_level: ConfidenceLevel = "medium"
    human_review_required: bool = False
    payload: dict[str, Any] = Field(default_factory=dict)


class SimilarIncidentMatch(BaseModel):
    """Represent the similar incident match type.

    Key fields:
        incident_id: Structured value carried by this type.
        classification: Structured value carried by this type.
        similarity_score: Structured value carried by this type.
        summary: Structured value carried by this type.
        is_false_positive: Structured value carried by this type.
        warning: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    incident_id: str
    classification: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    summary: str = ""
    is_false_positive: bool = False
    warning: str = ""


class RiskAnalysisResult(BaseModel):
    """Represent the risk analysis result type.

    Key fields:
        schema_version: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        recommendation: Structured value carried by this type.
        decision_record: Structured value carried by this type.
        audit_entry: Structured value carried by this type.
        similar_incidents: Structured value carried by this type.
        governance: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    schema_version: str = AI_SCHEMA_VERSION
    incident_id: str
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    recommendation: AIRecommendation
    decision_record: DecisionRecord
    audit_entry: AnalystAuditEntry
    similar_incidents: list[SimilarIncidentMatch] = Field(default_factory=list)
    governance: dict[str, Any] = Field(default_factory=dict)
