"""Policy engine tests."""

from __future__ import annotations

from windows_network_toolkit.decision.decision_model import DecisionResult, IncidentType
from windows_network_toolkit.decision.policy_engine import PolicyOutcome, evaluate_policy


def _decision(**kwargs: object) -> DecisionResult:
    base = {
        "decision_id": "d1",
        "incident_id": "i1",
        "incident_type": IncidentType.WININET_PROXY_DRIFT,
        "confidence": 0.88,
        "risk_level": "medium",
        "recommended_action": "DISABLE_WININET_PROXY_WITH_CONFIRMATION",
        "requires_confirmation": True,
        "reasoning": "test",
    }
    base.update(kwargs)
    return DecisionResult(**base)  # type: ignore[arg-type]


def test_policy_preview_by_default() -> None:
    policy = evaluate_policy(_decision(), dry_run=True)
    assert policy["dry_run"] is True
    assert "remediation_preview" in policy["allowed_actions"] or policy["outcome"] in {
        PolicyOutcome.ALLOW_WITH_CONFIRMATION.value,
        PolicyOutcome.REQUIRE_ROLLBACK_PLAN.value,
    }


def test_policy_blocks_low_confidence_live() -> None:
    policy = evaluate_policy(
        _decision(confidence=0.5),
        dry_run=False,
        evidence_level="OBSERVED_ONLY",
    )
    assert "disable_wininet_proxy" in policy["blocked_actions"]


def test_remediation_preview_dry_run() -> None:
    from windows_network_toolkit.remediation import preview_proxy_disable

    preview = preview_proxy_disable(dry_run=True)
    assert preview["dry_run"] is True
    assert preview["required_confirmation"]
