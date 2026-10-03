"""Federated orchestrator, audit, and replay."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from platform_core.models import utc_now_iso
from src.decision_engine.decision_engine import content_digest
from src.decision_engine.scoring import EvidenceItem
from src.platform_core.contracts import EvidenceBundle
from src.platform_core.contracts import EvidenceItem as ContractEvidenceItem
from src.platform_core.decision_intelligence.adapters import ADAPTERS
from src.platform_core.decision_intelligence.models import (
    AuditRecord,
    ExplainabilityGraph,
    FederatedDecisionResult,
    FederatedEvidenceInput,
)


def bundle_to_scoring_evidence(bundle: EvidenceBundle) -> list[EvidenceItem]:
    """Return bundle to scoring evidence.

    Args:
        bundle: bundle supplied by the caller.

    Returns:
        The computed `list[EvidenceItem]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    items: list[EvidenceItem] = []
    for item in bundle.items:
        items.append(
            EvidenceItem(
                evidence_id=_map_signal_to_scoring_id(item.signal, item.observed_value),
                label=item.signal,
                weight=min(1.0, max(0.1, item.confidence or 0.5)),
                supports_decision=True,
                detail=item.observed_value,
            )
        )
    _inject_derived_evidence(items, bundle)
    return items


def _map_signal_to_scoring_id(signal: str, value: str) -> str:
    s = signal.lower()
    if "proxy" in s and "enable" in s:
        return "proxy_enabled"
    if "listener" in s:
        return "listener_absent" if value.lower() in {"false", "0"} else "listener_on_proxy_port"
    if "browser" in s or "https" in s:
        return "browser_fail"
    if "ping" in s or "dns" in s:
        return "ping_ok"
    if "tls" in s or "mitm" in s:
        return "tls_mismatch"
    if "writer" in s:
        return "missing_writer"
    return signal.replace(" ", "_")[:48]


def _inject_derived_evidence(items: list[EvidenceItem], bundle: EvidenceBundle) -> None:
    signals = {i.signal.lower(): i.observed_value for i in bundle.items}
    if any("proxy" in k for k in signals) and not any(
        e.evidence_id == "missing_writer" for e in items
    ):
        items.append(
            EvidenceItem(
                evidence_id="missing_writer",
                label="missing_writer",
                weight=0.6,
                supports_decision=False,
                detail="Writer telemetry not in bundle",
            )
        )
    if signals.get("browser_https_failed") == "true" or signals.get("browser_fail"):
        if not any(e.evidence_id == "browser_fail" for e in items):
            items.append(
                EvidenceItem(
                    evidence_id="browser_fail",
                    label="browser_https_failed",
                    weight=0.85,
                    supports_decision=True,
                )
            )


def build_evidence_input_from_fixture(
    payload: dict[str, Any], *, incident_id: str | None = None
) -> FederatedEvidenceInput:
    """Build evidence input from fixture.

    Args:
        payload: payload supplied by the caller.
        incident_id: incident id supplied by the caller.

    Returns:
        The computed `FederatedEvidenceInput` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    iid = incident_id or payload.get("case_id") or f"inc-{uuid.uuid4().hex[:12]}"
    state = payload.get("proxy_state") or {}
    owner = payload.get("proxy_owner") or {}
    classification = payload.get("classification") or {}
    items: list[ContractEvidenceItem] = []

    if state.get("wininet_proxy_enabled") is not None:
        items.append(
            ContractEvidenceItem(
                evidence_id="ev-registry-enable",
                event_id=iid,
                timestamp_utc=state.get("timestamp_utc", utc_now_iso()),
                source="registry",
                signal="wininet_proxy_enabled",
                observed_value=str(state.get("wininet_proxy_enabled")),
                tier="OBSERVED_ONLY",
                confidence=0.9,
            )
        )
    if state.get("wininet_proxy_server"):
        items.append(
            ContractEvidenceItem(
                evidence_id="ev-registry-server",
                event_id=iid,
                timestamp_utc=utc_now_iso(),
                source="registry",
                signal="wininet_proxy_server",
                observed_value=str(state.get("wininet_proxy_server")),
                tier="OBSERVED_ONLY",
            )
        )
    items.append(
        ContractEvidenceItem(
            evidence_id="ev-listener",
            event_id=iid,
            timestamp_utc=utc_now_iso(),
            source="netstat",
            signal="listener_found",
            observed_value=str(bool(owner.get("listener_found"))),
            tier="CORRELATED" if owner.get("listener_found") else "OBSERVED_ONLY",
        )
    )
    if classification.get("primary_classification") == "DEAD_PROXY_CONFIG":
        items.append(
            ContractEvidenceItem(
                evidence_id="ev-browser-fail",
                event_id=iid,
                timestamp_utc=utc_now_iso(),
                source="symptom",
                signal="browser_https_failed",
                observed_value="true",
                tier="OBSERVED_ONLY",
            )
        )
        items.append(
            ContractEvidenceItem(
                evidence_id="ev-ping-ok",
                event_id=iid,
                timestamp_utc=utc_now_iso(),
                source="network",
                signal="ping_ok",
                observed_value="true",
                tier="OBSERVED_ONLY",
            )
        )

    bundle = EvidenceBundle(
        bundle_id=f"bun-{uuid.uuid4().hex[:8]}",
        incident_id=iid,
        created_at=utc_now_iso(),
        tier="OBSERVED_ONLY",
        items=items,
        summary=classification.get("reasoning", "Fixture evidence bundle"),
    )
    proof = payload.get("proof") or {}
    return FederatedEvidenceInput(
        incident_id=iid,
        bundle=bundle,
        classification=classification.get("primary_classification"),
        proof_status=(proof.get("conclusion") or {}).get("status"),
        limitations=list(classification.get("limitations") or [])
        + list(proof.get("limitations") or []),
    )


def _build_explainability(recommendations, shared: list[EvidenceItem]) -> ExplainabilityGraph:
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    for e in shared:
        nodes.append({"id": e.evidence_id, "type": "evidence", "label": e.label})
    for rec in recommendations:
        nid = rec.recommendation_id
        nodes.append({"id": nid, "type": "recommendation", "domain": rec.domain.value})
        for trace in rec.evidence_trace:
            rel = "missing" if trace.role == "missing" else "supports"
            edges.append({"from": trace.evidence_id, "to": nid, "relation": rel})
    return ExplainabilityGraph(nodes=nodes, edges=edges)


def evaluate_federated(evidence: FederatedEvidenceInput) -> FederatedDecisionResult:
    """Evaluate federated.

    Args:
        evidence: evidence supplied by the caller.

    Returns:
        The computed `FederatedDecisionResult` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    shared = bundle_to_scoring_evidence(evidence.bundle)
    recommendations = []
    for adapter in ADAPTERS:
        top, all_scored = adapter.score_best(evidence, shared)
        rec = adapter.to_recommendation(top, all_scored, evidence, shared)
        recommendations.append(rec)

    digest_payload = {
        "incident_id": evidence.incident_id,
        "evidence": [e.model_dump() for e in shared],
        "recommendations": [
            {"domain": r.domain.value, "id": r.recommendation_id, "score": r.explain.final_score}
            for r in recommendations
        ],
    }
    digest = content_digest(digest_payload)
    replay_anchor = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    audit = AuditRecord(
        audit_id=f"aud-{uuid.uuid4().hex[:12]}",
        incident_id=evidence.incident_id,
        timestamp_utc=utc_now_iso(),
        content_digest=digest,
        domains_evaluated=[r.domain.value for r in recommendations],
        policy_postures={r.domain.value: r.policy_posture for r in recommendations},
        replay_anchor=replay_anchor,
    )

    return FederatedDecisionResult(
        incident_id=evidence.incident_id,
        recommendations=recommendations,
        explainability=_build_explainability(recommendations, shared),
        audit=audit,
        metadata={"classification": evidence.classification, "proof_status": evidence.proof_status},
    )


def replay_verify(snapshot: dict[str, Any], expected_digest: str) -> bool:
    """Recompute digest from snapshot and compare."""
    return content_digest(snapshot) == expected_digest
