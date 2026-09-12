"""SRE investigation orchestrator — wires reliability pipeline into event-sourced incidents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from platform_core.reliability.decision_engine import persist_decision, run_platform_decision
from platform_core.reliability.event_pipeline import normalize_raw_observation
from platform_core.reliability.policy_config import PolicyConfig

from .event_store import append_domain_event
from .failure_domains import DomainDegradedError, FailureDomain, execute_in_domain
from .incident_aggregate import IncidentAggregate
from .models import IncidentPhase
from .rca import build_rca_report


def run_investigation(
    incident_id: str,
    observations: list[dict[str, Any]],
    *,
    endpoint_id: str | None = None,
    context: dict[str, Any] | None = None,
    requested_action: str | None = None,
    explicit_confirmation: bool = False,
) -> dict[str, Any]:
    """Run full investigation: decision pipeline inside failure domains + incident events.

    Correctness guarantees:
    - Each stage isolated in failure domain bulkhead
    - All outputs appended to canonical domain event log
    - Decision persisted with aligned event_ids for replay
  """
    agg = IncidentAggregate(incident_id)
    proj = agg.projection
    ep = endpoint_id or proj.endpoint_id or "local"

    if proj.phase == IncidentPhase.DETECTED:
        agg.acknowledge(actor="investigation")
    if proj.phase in (IncidentPhase.DETECTED, IncidentPhase.ACKNOWLEDGED):
        agg.start_investigation(actor="investigation")

    def _run_decision():
        policy = PolicyConfig.from_yaml_path(Path("config/platform_policy.yaml"))
        return run_platform_decision(
            observations,
            endpoint_id=ep,
            requested_action=requested_action,
            explicit_confirmation=explicit_confirmation,
            context=context,
            policy=policy,
        )

    try:
        record = execute_in_domain(
            FailureDomain.INVESTIGATION,
            _run_decision,
            correlation_id=incident_id,
        )
    except DomainDegradedError as exc:
        return {
            "incident_id": incident_id,
            "status": "degraded",
            "error": str(exc),
            "failure_domain": FailureDomain.INVESTIGATION.value,
        }

    events = [
        normalize_raw_observation(o, endpoint_id=ep).model_copy(update={"event_id": eid})
        for o, eid in zip(observations, record.event_ids, strict=False)
    ]

    def _persist():
        persist_decision(record, events=events)
        append_domain_event(
            aggregate_id=incident_id,
            aggregate_type="incident",
            event_type="decision.recorded",
            correlation_id=incident_id,
            payload=record.model_dump(mode="json"),
            failure_domain="audit",
        )

    execute_in_domain(FailureDomain.AUDIT, _persist, correlation_id=incident_id)

    hyp_event = agg.record_hypothesis_ranking(
        run_id=record.run_id,
        accepted_hypothesis=record.accepted_hypothesis,
        state_path=record.state_path,
        event_ids=record.event_ids,
        policy_outcome=record.policy_outcome,
    )

    has_proof = any(
        str(line).lower().find("no proof") < 0 and "proof" in str(line).lower()
        for line in record.limitations
    ) or "ROOT_CAUSE_IDENTIFIED" in record.state_path

    rca = build_rca_report(incident_id, decision=record)
    if has_proof or record.accepted_hypothesis:
        tier = rca.confidence_tier
        agg.identify_root_cause(
            root_cause_summary=rca.root_cause_statement,
            accepted_hypothesis=record.accepted_hypothesis,
            confidence_tier=tier,
            evidence_event_ids=record.event_ids,
            limitations=rca.limitations,
        )

    return {
        "incident_id": incident_id,
        "status": "ok",
        "run_id": record.run_id,
        "policy_outcome": record.policy_outcome,
        "state_path": record.state_path,
        "accepted_hypothesis": record.accepted_hypothesis,
        "rca": rca.model_dump(mode="json"),
        "hypothesis_event_id": hyp_event.event_id,
        "limitations": record.limitations,
    }
