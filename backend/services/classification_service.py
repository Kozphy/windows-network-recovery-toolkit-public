"""Risk Classification Service — deterministic pipeline + hypothesis generation."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session

from backend.db.models import HypothesisRecord, IncidentRecord
from backend.services.base import TenantContext
from src.platform_core.governance.human_review import REVIEW_CLASSES
from windows_network_toolkit.analytics_pipeline import run_endpoint_analytics_pipeline


def _confidence_ordinal(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.65:
        return "medium"
    if score >= 0.4:
        return "low"
    return "very_low"


class ClassificationService:
    """Represent classification service data used by the toolkit.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

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

    def classify_fixture(self, fixture: dict[str, Any]) -> dict[str, Any]:
        """Run existing deterministic analytics pipeline."""
        return run_endpoint_analytics_pipeline(fixture=fixture)

    def propose_hypothesis(
        self,
        *,
        observation_id: str | None,
        evidence_event_id: str | None,
        classification: str,
        confidence_score: float,
        limitations: list[str] | None = None,
    ) -> HypothesisRecord:
        """Propose hypothesis.

        Args:
            observation_id: The observation id value supplied by the caller.
            evidence_event_id: The evidence event id value supplied by the caller.
            classification: The classification value supplied by the caller.
            confidence_score: The confidence score value supplied by the caller.
            limitations: The limitations value supplied by the caller.

        Returns:
            The HypothesisRecord result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        hyp_id = f"hyp-{uuid.uuid4().hex[:12]}"
        row = HypothesisRecord(
            hypothesis_id=hyp_id,
            tenant_id=self._ctx.tenant_id,
            observation_id=observation_id,
            evidence_event_id=evidence_event_id,
            label=classification,
            confidence_score=confidence_score,
            confidence_ordinal=_confidence_ordinal(confidence_score),
            status="proposed",
            limitations=limitations
            or ["Hypothesis is triage — not causation proof or malware verdict."],
        )
        self._session.add(row)
        self._session.flush()
        return row

    def store_incident_from_pipeline(
        self,
        *,
        evidence_event_id: str,
        endpoint_id: str,
        incident_payload: dict[str, Any],
    ) -> IncidentRecord:
        """Store incident from pipeline.

        Args:
            evidence_event_id: The evidence event id value supplied by the caller.
            endpoint_id: The endpoint id value supplied by the caller.
            incident_payload: The incident payload value supplied by the caller.

        Returns:
            The IncidentRecord result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        incident_id = str(
            incident_payload.get("incident_id") or f"INC-{uuid.uuid4().hex[:8].upper()}"
        )
        row = IncidentRecord(
            incident_id=incident_id,
            evidence_event_id=evidence_event_id,
            endpoint_id=endpoint_id,
            primary_classification=str(
                incident_payload.get("incident_class")
                or incident_payload.get("primary_classification")
                or "UNKNOWN"
            ),
            secondary_signals=list(incident_payload.get("secondary_signals") or []),
            proof_tier=str(
                incident_payload.get("proof_tier")
                or incident_payload.get("evidence_tier")
                or "T1_STATE_EVIDENCE"
            ),
            confidence=float(incident_payload.get("confidence") or 0.5),
            limitations=list(incident_payload.get("limitations") or []),
            tenant_id=self._ctx.tenant_id,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def needs_human_review(self, classification: str) -> bool:
        """Needs human review.

        Args:
            classification: The classification value supplied by the caller.

        Returns:
            The bool result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return classification.upper() in REVIEW_CLASSES
