"""Decision pipeline: Observation → Hypothesis → Evidence → Confidence → Decision → Audit."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlmodel import Session

from backend.db.models import HumanReviewItem, PlatformDecisionRecord
from backend.services.audit_service import AuditService
from backend.services.base import TenantContext, principal_context
from backend.services.classification_service import ClassificationService
from backend.services.evidence_service import EvidenceService
from backend.services.policy_service import PolicyService
from backend.services.reporting_service import ReportingService
from src.platform_core.governance.human_review import REVIEW_CLASSES


def _confidence_label(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.65:
        return "medium"
    if score >= 0.4:
        return "low"
    return "very_low"


@dataclass
class PipelineResult:
    """Represent pipeline result data used by the toolkit.

    Attributes:
        correlation_id: Field or variant describing correlation id evidence or state.
        observation_id: Field or variant describing observation id evidence or state.
        evidence_event_id: Field or variant describing evidence event id evidence or state.
        hypothesis_id: Field or variant describing hypothesis id evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        incident_id: Field or variant describing incident id evidence or state.
        classification: Field or variant describing classification evidence or state.
        confidence_score: Field or variant describing confidence score evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    correlation_id: str
    observation_id: str
    evidence_event_id: str
    hypothesis_id: str
    decision_id: str
    incident_id: str | None
    classification: str
    confidence_score: float
    policy_outcome: str
    human_approval_required: bool
    human_review_id: str | None
    limitations: list[str]


class DecisionPipeline:
    """Orchestrates the six-stage enterprise decision loop."""

    def __init__(self, session: Session, ctx: TenantContext) -> None:
        """Initialize the object with caller supplied state.

        Args:
            session: Database session used to read or persist records.
            ctx: The ctx value supplied by the caller.

        Returns:
            None.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        self._session = session
        self._ctx = ctx
        self._evidence = EvidenceService(session, ctx)
        self._classification = ClassificationService(session, ctx)
        self._policy = PolicyService(session, ctx)
        self._audit = AuditService(session, ctx)
        self._reporting = ReportingService(session, ctx)

    def run(
        self,
        *,
        endpoint_id: str,
        signal_type: str,
        raw_observation: dict[str, Any],
        evidence_type: str = "proxy_state",
        requested_action: str = "observe",
    ) -> PipelineResult:
        """Run.

        Args:
            endpoint_id: The endpoint id value supplied by the caller.
            signal_type: The signal type value supplied by the caller.
            raw_observation: The raw observation value supplied by the caller.
            evidence_type: The evidence type value supplied by the caller.
            requested_action: The requested action value supplied by the caller.

        Returns:
            The PipelineResult result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        correlation_id = f"corr-{uuid.uuid4().hex[:12]}"

        # 1. Observation
        observation = self._evidence.record_observation(
            endpoint_id=endpoint_id,
            signal_type=signal_type,
            raw_observation=raw_observation,
            correlation_id=correlation_id,
        )
        self._audit.append(
            event_type="ObservationRecorded",
            resource_type="observation",
            resource_id=observation.observation_id,
            payload={"endpoint_id": endpoint_id, "signal_type": signal_type},
            correlation_id=correlation_id,
        )

        # 2. Evidence (structured package from observation)
        fixture = {"proxy_state": raw_observation, "endpoint_id": endpoint_id}
        evidence_row, _ = self._evidence.ingest_evidence(
            endpoint_id=endpoint_id,
            evidence_type=evidence_type,
            raw_snapshot=fixture,
            observation_id=observation.observation_id,
        )
        self._audit.append(
            event_type="EvidenceIngested",
            resource_type="evidence",
            resource_id=evidence_row.event_id,
            payload={"evidence_type": evidence_type},
            correlation_id=correlation_id,
        )

        # 3. Classification (deterministic)
        payload = self._classification.classify_fixture(fixture)
        incidents = payload.get("incidents") or []
        if not incidents:
            classification = "NO_INCIDENT"
            confidence = 0.0
            incident_id = None
            limitations = ["No incident produced — observation only."]
        else:
            inc = incidents[0]
            classification = str(
                inc.get("incident_class") or inc.get("primary_classification") or "UNKNOWN"
            )
            confidence = float(inc.get("confidence") or 0.5)
            limitations = list(inc.get("limitations") or [])
            incident_row = self._classification.store_incident_from_pipeline(
                evidence_event_id=evidence_row.event_id,
                endpoint_id=endpoint_id,
                incident_payload=inc,
            )
            incident_id = incident_row.incident_id

        # 4. Hypothesis
        hypothesis = self._classification.propose_hypothesis(
            observation_id=observation.observation_id,
            evidence_event_id=evidence_row.event_id,
            classification=classification,
            confidence_score=confidence,
            limitations=limitations,
        )
        self._audit.append(
            event_type="HypothesisProposed",
            resource_type="hypothesis",
            resource_id=hypothesis.hypothesis_id,
            payload={"label": classification, "confidence": confidence},
            correlation_id=correlation_id,
        )

        # 5. Policy + Confidence → Decision
        needs_review = self._classification.needs_human_review(classification)
        policy_result = self._policy.evaluate(
            classification=classification,
            confidence_score=confidence,
            evidence_tier=str(incidents[0].get("proof_tier") if incidents else "T1_STATE_EVIDENCE"),
            requested_action=requested_action,
            requires_human_review=needs_review,
        )
        decision_id = f"pdec-{uuid.uuid4().hex[:12]}"
        execution_authority = "preview_only"
        if policy_result["policy_outcome"] == "BLOCK":
            execution_authority = "blocked"
        elif policy_result["requires_human_approval"]:
            execution_authority = "requires_approval"

        decision = PlatformDecisionRecord(
            decision_id=decision_id,
            tenant_id=self._ctx.tenant_id,
            incident_id=incident_id,
            hypothesis_id=hypothesis.hypothesis_id,
            evidence_event_id=evidence_row.event_id,
            confidence_score=confidence,
            confidence_label=_confidence_label(confidence),
            policy_outcome=policy_result["policy_outcome"],
            recommended_action=policy_result.get("yaml_decision", "OBSERVE"),
            execution_authority=execution_authority,
            human_approval_required=policy_result["requires_human_approval"],
            human_approval_status="pending"
            if policy_result["requires_human_approval"]
            else "not_required",
            actor=self._ctx.actor_id,
            rationale=policy_result.get("rationale", ""),
            limitations=list(policy_result.get("limitations") or []),
        )
        self._session.add(decision)
        self._session.flush()

        # 6. Human review queue + Audit
        review_id: str | None = None
        if classification.upper() in REVIEW_CLASSES and incident_id:
            review_id = f"rev-{uuid.uuid4().hex[:12]}"
            review = HumanReviewItem(
                review_id=review_id,
                incident_id=incident_id,
                evidence_id=evidence_row.event_id,
                classification=classification,
                status="PENDING_REVIEW",
            )
            self._session.add(review)
            self._session.flush()

        self._audit.append(
            event_type="DecisionRecorded",
            resource_type="decision",
            resource_id=decision_id,
            payload={
                "classification": classification,
                "policy_outcome": policy_result["policy_outcome"],
                "confidence_score": confidence,
            },
            correlation_id=correlation_id,
        )

        all_limitations = list(limitations) + list(policy_result.get("limitations") or [])
        return PipelineResult(
            correlation_id=correlation_id,
            observation_id=observation.observation_id,
            evidence_event_id=evidence_row.event_id,
            hypothesis_id=hypothesis.hypothesis_id,
            decision_id=decision_id,
            incident_id=incident_id,
            classification=classification,
            confidence_score=confidence,
            policy_outcome=policy_result["policy_outcome"],
            human_approval_required=policy_result["requires_human_approval"],
            human_review_id=review_id,
            limitations=all_limitations,
        )


def run_decision_pipeline(
    session: Session,
    principal: Any,
    *,
    endpoint_id: str,
    signal_type: str,
    raw_observation: dict[str, Any],
    evidence_type: str = "proxy_state",
    requested_action: str = "observe",
) -> PipelineResult:
    """Run decision pipeline.

    Args:
        session: Database session used to read or persist records.
        principal: The principal value supplied by the caller.
        endpoint_id: The endpoint id value supplied by the caller.
        signal_type: The signal type value supplied by the caller.
        raw_observation: The raw observation value supplied by the caller.
        evidence_type: The evidence type value supplied by the caller.
        requested_action: The requested action value supplied by the caller.

    Returns:
        The PipelineResult result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    ctx = principal_context(principal)
    return DecisionPipeline(session, ctx).run(
        endpoint_id=endpoint_id,
        signal_type=signal_type,
        raw_observation=raw_observation,
        evidence_type=evidence_type,
        requested_action=requested_action,
    )
