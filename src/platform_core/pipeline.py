"""Canonical decision pipeline orchestrator."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platform_core.models import utc_now_iso
from src.platform_core.audit.writer import append_audit, reset_chain_for_tests
from src.platform_core.contracts import AuditActionType, EvidenceBundle, EvidenceItem, Hypothesis
from src.platform_core.decision.engine import build_decision
from src.platform_core.evidence.state_machine import EvidenceStateMachine
from src.platform_core.hypothesis.engine import build_hypothesis
from src.platform_core.policy.engine import evaluate_policy


@dataclass
class PipelineResult:
    """Represent the pipeline result type.

    Key fields:
        bundle: Structured value carried by this type.
        hypothesis: Structured value carried by this type.
        decision: Structured value carried by this type.
        policy: Structured value carried by this type.
        audit_ids: Structured value carried by this type.

    Side effects:
        None.
    """
    bundle: EvidenceBundle
    hypothesis: Hypothesis
    decision: Any
    policy: Any
    audit_ids: list[str]


def _load_signals(jsonl_path: Path | None, signals: dict[str, Any] | None) -> dict[str, Any]:
    if signals:
        return dict(signals)
    out: dict[str, Any] = {}
    if jsonl_path and jsonl_path.is_file():
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if isinstance(row, dict):
                if "signal" in row:
                    out[str(row["signal"])] = row.get("observed_value", row.get("value"))
                else:
                    out.update({k: v for k, v in row.items() if k not in {"timestamp", "timestamp_utc"}})
    return out


def _build_bundle(signals: dict[str, Any], incident_id: str | None) -> EvidenceBundle:
    iid = incident_id or f"incident-{uuid.uuid4().hex[:12]}"
    sm = EvidenceStateMachine()
    tier = sm.apply_signals(signals)
    items: list[EvidenceItem] = []
    for idx, (sig, val) in enumerate(signals.items()):
        items.append(
            EvidenceItem(
                evidence_id=f"ev-{idx}",
                event_id=iid,
                timestamp_utc=utc_now_iso(),
                source="pipeline",
                signal=str(sig),
                observed_value=str(val),
                tier=tier,
            )
        )
    return EvidenceBundle(
        bundle_id=f"bun-{uuid.uuid4().hex[:12]}",
        incident_id=iid,
        created_at=utc_now_iso(),
        tier=tier,
        items=items,
        summary=f"Bundle with tier {tier}",
    )


def _classify_incident(signals: dict[str, Any]) -> tuple[str, str, str, float, bool]:
    from windows_network_toolkit.decision.hypothesis_engine import evaluate_incident

    temp_id = "pipeline-classify"
    legacy = evaluate_incident(signals, incident_id=temp_id)
    return (
        legacy.incident_type.value,
        legacy.recommended_action,
        legacy.reasoning,
        legacy.confidence,
        legacy.human_review_required,
    )


def run_decision_pipeline(
    *,
    signals: dict[str, Any] | None = None,
    jsonl_path: Path | str | None = None,
    incident_id: str | None = None,
    requested_action: str = "disable_wininet_proxy",
    dry_run: bool = True,
) -> PipelineResult:
    """Run decision pipeline.

    Args:
        signals: signals supplied by the caller.
        jsonl_path: jsonl path supplied by the caller.
        incident_id: incident id supplied by the caller.
        requested_action: requested action supplied by the caller.
        dry_run: dry run supplied by the caller.

    Returns:
        The computed `PipelineResult` value.

    Side effects:
        Executes the configured evaluation or processing flow.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    path = Path(jsonl_path) if jsonl_path else None
    sig = _load_signals(path, signals)
    bundle = _build_bundle(sig, incident_id)

    incident_type, action, reasoning, confidence, human_review = _classify_incident(sig)
    hypothesis = build_hypothesis(
        bundle,
        incident_type=incident_type,
        title=incident_type,
        explanation=reasoning,
    )
    hypothesis = hypothesis.model_copy(update={"confidence": confidence})

    decision = build_decision(
        bundle,
        hypothesis,
        recommended_action=action,
        requires_human_review=human_review,
    )
    policy = evaluate_policy(
        decision=decision,
        bundle=bundle,
        requested_action=requested_action,
        dry_run=dry_run,
    )

    audit_ids: list[str] = []
    audit_steps: list[tuple[AuditActionType, dict[str, Any]]] = [
        ("event_received", {"incident_id": bundle.incident_id}),
        ("evidence_attached", {"tier": bundle.tier, "count": len(bundle.items)}),
        ("hypothesis_created", {"hypothesis_id": hypothesis.hypothesis_id}),
        ("decision_created", {"decision_id": decision.decision_id}),
        ("policy_evaluated", {"outcome": policy.outcome}),
    ]
    for action_type, payload in audit_steps:
        rec = append_audit(
            action_type,
            trace_id=bundle.incident_id,
            decision_id=decision.decision_id,
            incident_id=bundle.incident_id,
            payload=payload,
        )
        audit_ids.append(rec.audit_id)

    return PipelineResult(
        bundle=bundle,
        hypothesis=hypothesis,
        decision=decision,
        policy=policy,
        audit_ids=audit_ids,
    )


__all__ = ["PipelineResult", "reset_chain_for_tests", "run_decision_pipeline"]
