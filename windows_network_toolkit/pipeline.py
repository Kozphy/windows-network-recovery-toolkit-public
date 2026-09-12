"""End-to-end incident pipeline: evidence → decision → policy → remediation preview.

Module responsibility:
    Orchestrate ERP-style incident evaluation for FastAPI diagnose/replay paths. Bridges
    ``src.platform_core.pipeline`` (canonical) and legacy WNT decision modules.

System placement:
    Used by ``windows_network_toolkit.platform.api`` and ``audit.replay`` — distinct from
    batch analytics in ``analytics_pipeline``.

Key invariants:
    * ``dry_run=True`` by default on remediation planning.
    * ``PipelineResult.audit_record`` captures decision/policy metadata for replay.

Side effects:
    Legacy branch may append audit via ``append_audit``; canonical branch returns audit_ids.

Audit Notes:
    Verify ``dry_run`` in ``audit_record`` before inferring remediation was executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from windows_network_toolkit.audit.jsonl_logger import append_audit
from windows_network_toolkit.decision.decision_model import DecisionResult, IncidentType
from windows_network_toolkit.decision.hypothesis_engine import evaluate_incident
from windows_network_toolkit.decision.policy_engine import evaluate_policy
from windows_network_toolkit.decision.remediation_planner import plan_remediation
from windows_network_toolkit.evidence.timeline_builder import TimelineBuilder


@dataclass
class PipelineResult:
    """Container for one incident pipeline run.

    Attributes:
        bundle: ``EvidenceBundle`` from the canonical or legacy timeline builder.
        decision: ``DecisionResult`` from hypothesis/canonical engine.
        policy: Policy evaluation dict (keys: ``outcome``, ``allowed_actions``, ``blocked_actions``,
            ``requires_confirmation``, ``dry_run``, ``rationale``).
        remediation: Remediation plan dict; always preview-only when ``dry_run=True``.
        timeline: List of timeline dicts (``timestamp``, ``signal``, ``observed_value``, ``severity``).
        audit_record: Audit metadata dict written by legacy path or populated from canonical
            ``audit_ids``. Always includes ``dry_run`` — verify it before inferring execution.
    """

    bundle: Any
    decision: Any
    policy: dict[str, Any]
    remediation: dict[str, Any]
    timeline: list[dict[str, Any]]
    audit_record: dict[str, Any]


def _to_legacy_decision(decision: Any) -> DecisionResult:
    if isinstance(decision, DecisionResult):
        return decision
    incident_type = decision.incident_type
    if isinstance(incident_type, str):
        try:
            incident_type = IncidentType(incident_type)
        except ValueError:
            incident_type = IncidentType.UNKNOWN_LOCAL_PROXY
    return DecisionResult(
        decision_id=decision.decision_id,
        incident_id=decision.incident_id,
        incident_type=incident_type,
        confidence=decision.confidence,
        risk_level=getattr(decision, "risk_level", "medium"),
        recommended_action=getattr(decision, "recommended_action", ""),
        reasoning=getattr(decision, "reasoning", ""),
        evidence_refs=list(getattr(decision, "evidence_refs", [])),
        human_review_required=getattr(decision, "requires_human_review", False),
    )


def _signals_from_bundle(bundle: Any) -> dict[str, Any]:
    signals: dict[str, Any] = {}
    for ev in bundle.events:
        signals[ev.signal.lower()] = ev.observed_value
        if ev.raw_data:
            for k, v in ev.raw_data.items():
                if k not in signals:
                    signals[k] = v
    return signals


def run_incident_pipeline(
    *,
    signals: dict[str, Any] | None = None,
    jsonl_path: Path | str | None = None,
    incident_id: str | None = None,
    dry_run: bool = True,
    use_canonical: bool = True,
) -> PipelineResult:
    """Run evidence → decision → policy → remediation preview pipeline.

    Args:
        signals: Optional signal dict for live evaluation.
        jsonl_path: Fixture JSONL for replay ingestion.
        incident_id: Optional incident id override for timeline builder.
        dry_run: When True, remediation plan is preview-only (default).
        use_canonical: When True (default), delegate to ``src.platform_core.pipeline``.

    Returns:
        PipelineResult with bundle, decision, policy, remediation, timeline, audit_record.

    Side effects:
        Legacy path may append audit JSONL; canonical path returns audit_ids in audit_record.
    """
    if use_canonical:
        from src.platform_core.pipeline import run_decision_pipeline as canonical_run

        cr = canonical_run(
            signals=signals,
            jsonl_path=jsonl_path,
            incident_id=incident_id,
            dry_run=dry_run,
        )
        timeline = [
            {
                "timestamp": item.timestamp_utc,
                "signal": item.signal,
                "observed_value": item.observed_value,
                "severity": "medium",
            }
            for item in cr.bundle.items
        ]
        policy_dict = (
            cr.policy.model_dump() if hasattr(cr.policy, "model_dump") else dict(cr.policy)
        )
        policy_dict["dry_run"] = dry_run
        remediation = plan_remediation(_to_legacy_decision(cr.decision), dry_run=dry_run)
        if hasattr(remediation, "model_dump"):
            remediation = remediation.model_dump()
        return PipelineResult(
            bundle=cr.bundle,
            decision=cr.decision,
            policy=policy_dict,
            remediation=remediation,
            timeline=timeline,
            audit_record={
                "action": "pipeline_run",
                "incident_id": cr.bundle.incident_id,
                "decision_id": cr.decision.decision_id,
                "incident_type": cr.decision.incident_type,
                "policy_outcome": policy_dict.get("outcome", ""),
                "dry_run": dry_run,
                "audit_ids": cr.audit_ids,
            },
        )

    builder = TimelineBuilder(incident_id=incident_id)
    if jsonl_path:
        builder.ingest_jsonl(Path(jsonl_path))
    if signals:
        for k, v in signals.items():
            builder.add_signal(k, v)
    bundle = builder.build(summary="ERP pipeline run")
    signal_map = signals or _signals_from_bundle(bundle)
    evidence_refs = [ev.event_id for ev in bundle.events]
    decision = evaluate_incident(
        signal_map, incident_id=bundle.incident_id, evidence_refs=evidence_refs
    )
    policy = evaluate_policy(decision, dry_run=dry_run)
    remediation = plan_remediation(decision, dry_run=dry_run)
    timeline = bundle.to_timeline_json()
    audit_record = append_audit(
        {
            "incident_id": bundle.incident_id,
            "action": "pipeline_run",
            "decision_id": decision.decision_id,
            "incident_type": decision.incident_type.value,
            "policy_outcome": policy["outcome"],
            "dry_run": dry_run,
        }
    )
    return PipelineResult(
        bundle=bundle,
        decision=decision,
        policy=policy,
        remediation=remediation,
        timeline=timeline,
        audit_record=audit_record,
    )
