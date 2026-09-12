"""Bad-gateway diagnostic runner integrated with platform pipeline.

Module responsibility:
    Collect probes, classify cause, build platform evidence/decision envelope, optional audit.

System placement:
    Invoked by ``cmd_bad_gateway_diagnose`` and ``network_recovery.auto_fix``.

Key invariants:
    * Probes via ``collect_all`` are read-only.
    * ``dry_run`` gates policy evaluation only; probes still run.

Side effects:
    May append platform audit via ``append_audit`` when configured.

Audit Notes:
    * Review returned ``policy_gate`` and ``safety_notes`` before any remediation.
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.platform_core.audit.writer import append_audit
from src.platform_core.contracts import EvidenceBundle, EvidenceItem
from src.platform_core.decision.engine import build_decision
from src.platform_core.evidence.explanations import build_explanation
from src.platform_core.evidence.state_machine import EvidenceStateMachine
from src.platform_core.hypothesis.engine import build_hypothesis
from src.platform_core.policy.engine import evaluate_policy

from .classifier import classify_cause, headline
from .collectors import collect_all
from .url import parse_target


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signals_from_probes(probes: dict[str, Any]) -> dict[str, Any]:
    wininet = probes.get("wininet_proxy") or {}
    http_sys = probes.get("http_system_proxy") or {}
    http_dir = probes.get("http_direct") or {}
    dns = probes.get("dns") or {}
    tcp = probes.get("tcp") or {}
    local = probes.get("local_proxy_process") or {}
    return {
        "dns_ok": dns.get("ok"),
        "tcp_ok": tcp.get("ok"),
        "browser_https_failed": http_sys.get("status_code") in {502, 504},
        "proxy_bypass_succeeded": http_dir.get("status_code") == 200,
        "wininet_proxy_enabled": int(wininet.get("proxy_enable") or 0) == 1,
        "proxy_server_localhost": "127.0.0.1" in str(wininet.get("proxy_server") or ""),
        "listener_on_proxy_port": local.get("detected"),
        "path_validated": http_dir.get("status_code") == 200 and http_sys.get("status_code") in {502, 504},
    }


def run_bad_gateway_diagnose(
    url: str,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: dict[str, Any] | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Run read-only bad-gateway diagnostic; returns audit-ready JSON report."""
    run_fn = run or subprocess.run
    target = parse_target(url)
    probes = collect_all(url, run=run_fn, timeout=timeout, inject=inject)

    cause, confidence, action, safety_notes = classify_cause(probes)
    signals = _signals_from_probes(probes)
    sm = EvidenceStateMachine()
    tier = sm.apply_signals(signals)
    explanation = build_explanation(
        incident_type=cause,
        evidence_tier=tier,
        confidence=confidence,
        signals=signals,
    )

    incident_id = f"bg-{uuid.uuid4().hex[:12]}"
    items = [
        EvidenceItem(
            evidence_id=f"ev-{i}",
            event_id=incident_id,
            timestamp_utc=_now(),
            source="bad_gateway_diagnose",
            signal=k,
            observed_value=str(v),
            tier=tier,
        )
        for i, (k, v) in enumerate(signals.items())
    ]
    bundle = EvidenceBundle(
        bundle_id=f"bun-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        created_at=_now(),
        tier=tier,
        items=items,
        summary=headline(cause),
    )
    hypothesis = build_hypothesis(
        bundle, incident_type=cause, title=headline(cause), explanation=explanation.why_selected
    ).model_copy(update={"confidence": confidence})
    decision = build_decision(
        bundle,
        hypothesis,
        recommended_action=action,
        requires_human_review=cause in {"LOCAL_PROXY_MISCONFIG", "LOCAL_LOOPBACK_PROXY"},
    )
    policy = evaluate_policy(decision=decision, bundle=bundle, requested_action=action, dry_run=dry_run)

    audit_id = str(uuid.uuid4())
    append_audit(
        "decision_created",
        trace_id=incident_id,
        decision_id=decision.decision_id,
        incident_id=incident_id,
        payload={"diagnostic": "bad_gateway", "cause": cause, "url": url},
    )

    return {
        "schema_version": "wnt.bad_gateway.v1",
        "audit_id": audit_id,
        "timestamp": _now(),
        "url": target.url,
        "dns": probes.get("dns"),
        "tcp": probes.get("tcp"),
        "http_system_proxy": probes.get("http_system_proxy"),
        "http_direct": probes.get("http_direct"),
        "wininet_proxy": probes.get("wininet_proxy"),
        "winhttp_proxy": probes.get("winhttp_proxy"),
        "local_proxy_process": probes.get("local_proxy_process"),
        "classification": cause,
        "headline": headline(cause),
        "confidence": confidence,
        "recommended_action": action,
        "safety_notes": safety_notes,
        "observation": signals,
        "hypothesis": {
            "title": hypothesis.title,
            "explanation": explanation.why_selected,
            "missing_proof": explanation.missing_proof,
            "unjustified_claims": explanation.unjustified_claims,
            "conflicts": [c.__dict__ for c in explanation.conflicts],
        },
        "evidence": {"tier": tier, "items": [i.model_dump() for i in items]},
        "policy_gate": policy.model_dump(),
        "decision_id": decision.decision_id,
    }
