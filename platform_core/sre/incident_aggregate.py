"""Event-sourced incident aggregate — lifecycle commands emit domain events only."""

from __future__ import annotations

from typing import Any

from platform_core.reasoning_models import new_id

from .event_store import DomainEventStore, append_domain_event
from .models import (
    DomainEvent,
    DomainEventType,
    FailureDomainName,
    IncidentPhase,
    IncidentProjection,
)
from .projector import rebuild_incident


class IncidentAggregate:
    """Command handler for incident lifecycle — no mutable state, events only."""

    def __init__(self, incident_id: str, *, store: DomainEventStore | None = None) -> None:
        """Initialize the IncidentAggregate instance.

        Args:
            incident_id: Value supplied by the caller for incident id.
            store: Value supplied by the caller for store.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self.incident_id = incident_id
        self._store = store or DomainEventStore()

    @property
    def projection(self) -> IncidentProjection:
        """Provide projection behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return rebuild_incident(self.incident_id, store=self._store)

    def _append(
        self,
        event_type: DomainEventType,
        payload: dict[str, Any],
        *,
        causation_id: str | None = None,
        actor: str = "system",
        failure_domain: FailureDomainName | None = None,
    ) -> DomainEvent:
        return append_domain_event(
            aggregate_id=self.incident_id,
            aggregate_type="incident",
            event_type=event_type,
            correlation_id=self.incident_id,
            payload=payload,
            causation_id=causation_id,
            failure_domain=failure_domain,
            actor=actor,
            store=self._store,
        )

    @classmethod
    def open(
        cls,
        *,
        endpoint_id: str,
        title: str,
        severity: str = "medium",
        trigger_event_ids: list[str] | None = None,
        limitations: list[str] | None = None,
        store: DomainEventStore | None = None,
    ) -> IncidentAggregate:
        """Provide open behavior for toolkit workflows.

        Args:
            endpoint_id: Value supplied by the caller for endpoint id.
            title: Value supplied by the caller for title.
            severity: Value supplied by the caller for severity.
            trigger_event_ids: Value supplied by the caller for trigger event ids.
            limitations: Value supplied by the caller for limitations.
            store: Value supplied by the caller for store.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        incident_id = new_id("inc")
        agg = cls(incident_id, store=store)
        agg._append(
            "incident.detected",
            {
                "endpoint_id": endpoint_id,
                "title": title,
                "severity": severity,
                "trigger_event_ids": trigger_event_ids or [],
                "limitations": limitations
                or ["Observation != Proof; incident opened on correlated signals only."],
            },
            failure_domain="telemetry_ingest",
        )
        return agg

    def acknowledge(self, *, actor: str = "operator") -> DomainEvent:
        """Provide acknowledge behavior for toolkit workflows.

        Args:
            actor: Value supplied by the caller for actor.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        proj = self.projection
        if proj.phase not in (IncidentPhase.DETECTED,):
            raise ValueError(f"cannot acknowledge from phase {proj.phase}")
        return self._append("incident.acknowledged", {"actor": actor}, actor=actor)

    def start_investigation(self, *, actor: str = "operator") -> DomainEvent:
        """Provide start investigation behavior for toolkit workflows.

        Args:
            actor: Value supplied by the caller for actor.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        proj = self.projection
        if proj.phase not in (IncidentPhase.DETECTED, IncidentPhase.ACKNOWLEDGED):
            raise ValueError(f"cannot start investigation from phase {proj.phase}")
        return self._append(
            "incident.investigation_started",
            {"actor": actor},
            actor=actor,
            failure_domain="investigation",
        )

    def record_hypothesis_ranking(
        self,
        *,
        run_id: str,
        accepted_hypothesis: str,
        state_path: list[str],
        event_ids: list[str],
        policy_outcome: str,
        causation_id: str | None = None,
    ) -> DomainEvent:
        """Record hypothesis ranking for toolkit workflows.

        Args:
            run_id: Value supplied by the caller for run id.
            accepted_hypothesis: Value supplied by the caller for accepted hypothesis.
            state_path: Value supplied by the caller for state path.
            event_ids: Value supplied by the caller for event ids.
            policy_outcome: Value supplied by the caller for policy outcome.
            causation_id: Value supplied by the caller for causation id.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return self._append(
            "incident.hypothesis_ranked",
            {
                "run_id": run_id,
                "accepted_hypothesis": accepted_hypothesis,
                "state_path": state_path,
                "event_ids": event_ids,
                "policy_outcome": policy_outcome,
            },
            causation_id=causation_id,
            failure_domain="hypothesis_engine",
        )

    def identify_root_cause(
        self,
        *,
        root_cause_summary: str,
        accepted_hypothesis: str,
        confidence_tier: str,
        evidence_event_ids: list[str],
        limitations: list[str],
        actor: str = "investigation",
    ) -> DomainEvent:
        """Provide identify root cause behavior for toolkit workflows.

        Args:
            root_cause_summary: Value supplied by the caller for root cause summary.
            accepted_hypothesis: Value supplied by the caller for accepted hypothesis.
            confidence_tier: Value supplied by the caller for confidence tier.
            evidence_event_ids: Value supplied by the caller for evidence event ids.
            limitations: Value supplied by the caller for limitations.
            actor: Value supplied by the caller for actor.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        proj = self.projection
        if proj.phase not in (
            IncidentPhase.INVESTIGATING,
            IncidentPhase.ROOT_CAUSE_IDENTIFIED,
        ):
            raise ValueError(f"cannot identify root cause from phase {proj.phase}")
        if (
            confidence_tier not in ("proven", "contrast_tested")
            and "malware" in accepted_hypothesis.lower()
        ):
            limitations = list(limitations) + [
                "Malware-class hypothesis without proof tier — statement is investigative, not conviction."
            ]
        return self._append(
            "incident.root_cause_identified",
            {
                "root_cause_summary": root_cause_summary,
                "accepted_hypothesis": accepted_hypothesis,
                "confidence_tier": confidence_tier,
                "evidence_event_ids": evidence_event_ids,
                "limitations": limitations,
            },
            actor=actor,
            failure_domain="investigation",
        )

    def attempt_mitigation(
        self, *, action: str, outcome: str, actor: str = "operator"
    ) -> DomainEvent:
        """Provide attempt mitigation behavior for toolkit workflows.

        Args:
            action: Value supplied by the caller for action.
            outcome: Value supplied by the caller for outcome.
            actor: Value supplied by the caller for actor.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return self._append(
            "incident.mitigation_attempted",
            {"action": action, "outcome": outcome, "actor": actor},
            actor=actor,
            failure_domain="remediation",
        )

    def resolve(self, *, resolution: str, actor: str = "operator") -> DomainEvent:
        """Provide resolve behavior for toolkit workflows.

        Args:
            resolution: Value supplied by the caller for resolution.
            actor: Value supplied by the caller for actor.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        proj = self.projection
        if proj.phase == IncidentPhase.RESOLVED:
            raise ValueError("incident already resolved")
        return self._append(
            "incident.resolved",
            {"resolution": resolution, "actor": actor},
            actor=actor,
        )

    def mark_false_positive(self, *, reason: str, actor: str = "operator") -> DomainEvent:
        """Provide mark false positive behavior for toolkit workflows.

        Args:
            reason: Value supplied by the caller for reason.
            actor: Value supplied by the caller for actor.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return self._append(
            "incident.false_positive",
            {"reason": reason, "actor": actor},
            actor=actor,
        )
