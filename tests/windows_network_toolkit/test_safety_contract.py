"""WNT safety contract tests."""

from __future__ import annotations

from windows_network_toolkit.models import ClassificationResult
from windows_network_toolkit.platform.policy import evaluate_policy
from windows_network_toolkit.proxy_remediation import run_proxy_disable
from windows_network_toolkit.safety import is_blocked_action


def _dead_classification() -> ClassificationResult:
    return ClassificationResult(
        primary_classification="DEAD_PROXY_CONFIG",
        secondary_signals=["DEAD_LOCALHOST_PORT"],
        severity="medium",
        confidence=0.92,
        reasoning="dead proxy",
        evidence=[],
        recommended_next_actions=[],
        limitations=[],
    )


def test_proxy_disable_default_dry_run() -> None:
    from unittest.mock import patch

    with patch("windows_network_toolkit.proxy_remediation.platform.system", return_value="Windows"), patch(
        "windows_network_toolkit.proxy_remediation.read_proxy_registry"
    ) as mock_reg, patch(
        "windows_network_toolkit.proxy_remediation.collect_proxy_state_model"
    ) as mock_state, patch(
        "windows_network_toolkit.proxy_remediation.decide"
    ) as mock_decide:
        from src.core.models import ProxyRegistrySnapshot

        mock_reg.return_value = ProxyRegistrySnapshot(
            proxy_enable=1,
            proxy_server="127.0.0.1:59081",
            auto_config_url=None,
            auto_detect=None,
        )
        mock_state.return_value.to_dict.return_value = {"wininet_proxy_enabled": True}
        mock_decide.return_value = {
            "proof": {"hypothesis": "dead proxy"},
            "classification": {"limitations": []},
            "policy_decision": {},
        }
        result = run_proxy_disable(dry_run=True, confirm="")
    assert result["dry_run"] is True
    assert result["no_changes_made"] is True
    assert result["requires_confirmation"] is True


def test_proxy_disable_requires_exact_token() -> None:
    decision = evaluate_policy(
        "DISABLE_WININET_PROXY",
        _dead_classification(),
        dry_run=False,
        confirmation="WRONG",
    )
    assert decision.allowed is False


def test_blocked_actions() -> None:
    assert is_blocked_action("KILL_PROXY_PROCESS")
    assert is_blocked_action("FIREWALL_RESET")
    assert is_blocked_action("ADAPTER_DISABLE")
    assert is_blocked_action("WINHTTP_MODIFY")


def test_kill_process_denied() -> None:
    decision = evaluate_policy(
        "KILL_PROXY_PROCESS",
        _dead_classification(),
        dry_run=False,
        confirmation="KILL_PROXY_PROCESS",
    )
    assert decision.allowed is False
