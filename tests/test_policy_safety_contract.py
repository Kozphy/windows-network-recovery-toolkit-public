"""Policy safety contract — ALLOW / PREVIEW / BLOCK and destructive-action denials."""

from __future__ import annotations

import pytest

from platform_core.policy import OperatorContext, evaluate, validate_confirmation_phrase
from platform_core.remediation_registry import get_remediation_action
from src.policy.hypothesis_gates import PolicyDecision, decide_policy
from src.proof.contracts import ProofStatus


@pytest.mark.parametrize(
    "action",
    [
        "process_kill_forbidden",
        "adapter_disable_forbidden",
        "arbitrary_command_forbidden",
        "reset_firewall",
    ],
)
def test_destructive_or_forbidden_actions_never_execute(action: str) -> None:
    gate = evaluate({}, action, OperatorContext(role="admin", surface="api"))
    assert gate.execute_allowed is False


def test_registry_mutation_requires_typed_confirmation() -> None:
    for key in ("reset_proxy", "reset_dns"):
        defn = get_remediation_action(key)
        assert defn is not None
        assert defn.requires_confirmation
        assert defn.confirmation_phrase
        assert validate_confirmation_phrase(key, "") is False
        assert validate_confirmation_phrase(key, defn.confirmation_phrase) is True


def test_high_confidence_unproven_stays_preview() -> None:
    decision = decide_policy(confidence=0.95, proof_status="UNPROVEN")
    assert decision == PolicyDecision.PREVIEW


def test_proof_confirmed_allows_safe_tier_policy_row() -> None:
    decision = decide_policy(confidence=0.95, proof_status=ProofStatus.CONFIRMED.name)
    assert decision == PolicyDecision.ALLOW


def test_proof_rejected_blocks_even_with_high_confidence() -> None:
    decision = decide_policy(confidence=0.99, proof_status=ProofStatus.REJECTED.name)
    assert decision == PolicyDecision.BLOCK


def test_low_confidence_blocks() -> None:
    decision = decide_policy(confidence=0.10, proof_status="UNPROVEN")
    assert decision == PolicyDecision.BLOCK


def test_listener_correlation_module_states_not_writer_proof() -> None:
    from evidence.registry_writer_proof import build_registry_writer_proof

    payload = build_registry_writer_proof()
    limitation = payload["registry_writer_proof"]["limitation"].lower()
    assert "listener" in limitation or "correlation" in limitation
    assert "does not prove" in limitation or "not prove" in limitation


def test_heuristic_attribution_provider_never_emits_proof() -> None:
    from platform_core.attribution.polling import PollingHeuristicProvider

    out = PollingHeuristicProvider().attribute({"process_names_sample": ["node.exe"]})
    assert out.confidence != "proof"
