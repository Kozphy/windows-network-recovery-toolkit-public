"""Policy-gated remediation preview — dry-run default, never silent mutation.

Module responsibility:
    Build a proxy-drift remediation plan: policy evaluation, forward mutation preview,
    structured rollback preview package, and approval token gate.

System placement:
    Consumed by tests and portfolio demos; does not execute registry writes.

Key invariants:
    * ``dry_run=True`` default — ``can_execute`` in output is ``False`` unless token +
      policy allow and ``dry_run=False``.
    * Weak proof tiers may yield ``BLOCK`` or ``PREVIEW_ONLY`` policy outcomes.

Side effects:
    None — returns an in-memory plan dict only.

Audit Notes:
    Persist ``rollback_preview["rollback_audit_record"]`` when operators need a custody
    trail beyond the returned dict.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from src.platform_core.contracts import Decision, EvidenceBundle, EvidenceItem
from src.platform_core.evidence.guards import proof_inputs_from_signals
from src.platform_core.policy.approval import generate_approval_token, validate_approval_token
from src.platform_core.policy.engine import evaluate_policy

from .rollback import (
    build_proposed_mutation_preview,
    build_rollback_plan,
    build_rollback_preview_package,
    capture_pre_change_snapshot,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bundle_from_signals(signals: dict[str, Any], *, incident_id: str, tier: str = "OBSERVED_ONLY") -> EvidenceBundle:
    items = [
        EvidenceItem(
            evidence_id=f"ev-{i}",
            event_id=incident_id,
            timestamp_utc=_now(),
            source="remediation_planner",
            signal=k,
            observed_value=str(v),
            tier=tier,  # type: ignore[arg-type]
        )
        for i, (k, v) in enumerate(sorted(signals.items()))
    ]
    return EvidenceBundle(
        bundle_id=f"bundle-{incident_id}",
        incident_id=incident_id,
        created_at=_now(),
        tier=tier,  # type: ignore[arg-type]
        items=items,
    )


def plan_proxy_drift_remediation(
    *,
    incident_id: str,
    recommended_action: str = "disable_wininet_proxy",
    signals: dict[str, Any] | None = None,
    prior_proxy_enable: int = 1,
    prior_proxy_server: str = "",
    dry_run: bool = True,
    confirmation_token: str = "",
    expected_token: str = "",
) -> dict[str, Any]:
    """Generate remediation plan with policy gate, rollback preview, and approval metadata.

    Args:
        incident_id: Correlates evidence bundle and decision records.
        recommended_action: Registry action key (e.g. ``disable_wininet_proxy``).
        signals: Normalized observation dict; may include ``evidence_tier``, ``endpoint_id``.
        prior_proxy_enable: Value captured for rollback snapshot (default ``1``).
        prior_proxy_server: Prior ``ProxyServer`` string for rollback snapshot.
        dry_run: When ``True``, approval ``can_execute`` stays ``False``.
        confirmation_token: Operator token to validate against ``expected_token``.
        expected_token: Issued approval token; generated when empty.

    Returns:
        Plan dict with ``decision``, ``policy_gate``, ``previews``, ``rollback_plan``,
        ``rollback_preview`` (six-part package), and ``approval`` sub-dict.

    Side effects:
        None.

    Raises:
        ImportError: Caught internally — falls back to stub mutation preview if
            ``windows_network_toolkit.remediation.proxy_disable`` is unavailable.
    """
    signals = signals or {}
    bundle = _bundle_from_signals(signals, incident_id=incident_id, tier=str(signals.get("evidence_tier", "OBSERVED_ONLY")))
    decision = Decision(
        decision_id=f"dec-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        timestamp_utc=_now(),
        incident_type=str(signals.get("incident_type", "WININET_PROXY_DRIFT")),
        recommended_action=recommended_action,
        confidence=float(signals.get("confidence", 0.5)),
        risk_level="medium",
        evidence_tier=bundle.tier,
        requires_human_review=True,
        reasoning="Proxy drift with direct-path success suggests disabling WinINET proxy after approval.",
    )
    policy = evaluate_policy(
        decision=decision,
        bundle=bundle,
        requested_action=recommended_action,
        proof=proof_inputs_from_signals(signals),
        dry_run=dry_run,
    )

    previews: list[dict[str, Any]] = []
    if policy.outcome != "BLOCK":
        try:
            from windows_network_toolkit.remediation.proxy_disable import preview_proxy_disable

            previews.append(preview_proxy_disable(dry_run=True))
        except ImportError:
            previews.append({
                "action_id": recommended_action,
                "dry_run": True,
                "mutations": [{"argv": ["reg", "add", "..."], "human": "Set ProxyEnable=0 (preview)"}],
            })

    pre_snapshot = capture_pre_change_snapshot(
        endpoint_id=str(signals.get("endpoint_id", "local")),
        incident_id=incident_id,
        evidence=signals,
        proxy_enable=prior_proxy_enable,
        proxy_server=prior_proxy_server or "127.0.0.1:8080",
    )
    mutation_preview = build_proposed_mutation_preview(
        action_id=recommended_action,
        endpoint_id=str(signals.get("endpoint_id", "local")),
        dry_run=True,
        mutations=previews[0].get("mutations") if previews else None,
    )

    approval_token = expected_token or generate_approval_token()
    rollback_preview = build_rollback_preview_package(
        endpoint_id=str(signals.get("endpoint_id", "local")),
        incident_id=incident_id,
        action_id=recommended_action,
        pre_change_snapshot=pre_snapshot,
        proposed_mutation=mutation_preview,
        dry_run=True,
        approval_token=approval_token,
        confirmation_token=confirmation_token,
    )
    rollback = build_rollback_plan(
        action_id=recommended_action,
        prior_proxy_enable=prior_proxy_enable,
        prior_proxy_server=prior_proxy_server or "127.0.0.1:8080",
        dry_run=True,
    )
    approved = validate_approval_token(confirmation_token, approval_token) if confirmation_token else False
    can_execute = approved and policy.outcome in {"ALLOW", "REQUIRE_HUMAN_APPROVAL"} and not dry_run

    return {
        "incident_id": incident_id,
        "dry_run": dry_run,
        "decision": decision.model_dump(mode="json"),
        "policy_gate": policy.model_dump(mode="json"),
        "previews": previews,
        "rollback_plan": rollback,
        "rollback_preview": rollback_preview,
        "approval": {
            "required": policy.requires_approval or policy.outcome == "REQUIRE_HUMAN_APPROVAL",
            "token_expected_hint": approval_token[:8] + "…" if dry_run else "",
            "approved": approved,
            "can_execute": can_execute,
        },
        "blocked_reasons": policy.blocked_reasons,
        "rationale": policy.rationale,
        "safety_notes": [
            "No registry mutation without typed confirmation.",
            "Policy permission is not a safety guarantee.",
            "Rollback plan must be reviewed before execution.",
        ],
    }
