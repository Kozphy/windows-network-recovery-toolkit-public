"""Tests for dead-proxy guardian bridge (fixture-safe)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from windows_network_toolkit.proxy_guardian import run_proxy_guardian_once

# Windows-only surfaces: simulate the platform guard so Linux CI keeps this coverage.
pytestmark = pytest.mark.usefixtures("simulated_windows")


def test_guardian_skips_when_no_dead_proxy() -> None:
    with patch(
        "windows_network_toolkit.proxy_guardian._run_once",
        return_value={
            "classification": "NO_PROXY",
            "action_taken": "none",
            "dead_localhost_proxy": False,
        },
    ):
        out = run_proxy_guardian_once(dry_run=False)
    assert out["action_taken"] == "none"
    assert "remediation" not in out


def test_guardian_dry_run_dead_proxy() -> None:
    with patch(
        "windows_network_toolkit.proxy_guardian._run_once",
        return_value={
            "classification": "STALE_LOCALHOST_PROXY",
            "action_taken": "preview_only",
            "dead_localhost_proxy": True,
        },
    ) as guardian:
        out = run_proxy_guardian_once(dry_run=True)
    guardian.assert_called_once_with(dry_run=True, confirm="")
    assert out["action_taken"] == "would_remediate"
    assert out["classification"] == "DEAD_PROXY_CONFIG"


def test_guardian_skips_active_localhost_proxy() -> None:
    """Active dev proxy with listener must not be remediated."""
    with patch(
        "windows_network_toolkit.proxy_guardian._run_once",
        return_value={
            "classification": "KNOWN_DEV_PROXY",
            "action_taken": "none",
            "dead_localhost_proxy": False,
        },
    ):
        out = run_proxy_guardian_once(dry_run=False)
    assert out["action_taken"] == "none"
    assert "remediation" not in out


def test_guardian_applies_dead_proxy() -> None:
    with patch(
        "windows_network_toolkit.proxy_guardian._run_once",
        return_value={
            "classification": "STALE_LOCALHOST_PROXY",
            "action_taken": "remediated",
            "dead_localhost_proxy": True,
        },
    ) as guardian:
        out = run_proxy_guardian_once(dry_run=False)
    guardian.assert_called_once_with(dry_run=False, confirm="CLEAR_DEAD_LOCALHOST_PROXY")
    assert out["action_taken"] == "remediated"
    assert out["classification"] == "DEAD_PROXY_CONFIG"
