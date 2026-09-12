"""Tests for IPv6 path diagnose and prefer-IPv4 / restore remediation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from windows_network_toolkit.ipv6_path import (
    CONFIRMATION_PHRASE,
    PREFER_IPV4_BIT,
    RESTORE_CONFIRMATION_PHRASE,
    classify_ipv6_path,
    diagnose_ipv6_path,
    run_prefer_ipv4,
    run_restore_ipv6_preference,
)
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, is_blocked_action


def test_prefer_ipv4_token_registered() -> None:
    assert CONFIRMATION_TOKENS["PREFER_IPV4_OVER_IPV6"] == "PREFER_IPV4_OVER_IPV6"
    assert CONFIRMATION_TOKENS["RESTORE_IPV6_PREFERENCE"] == "RESTORE_IPV6_PREFERENCE"
    assert CONFIRMATION_PHRASE == "PREFER_IPV4_OVER_IPV6"
    assert RESTORE_CONFIRMATION_PHRASE == "RESTORE_IPV6_PREFERENCE"
    assert is_blocked_action("ADAPTER_DISABLE")


def test_classify_blackhole_pattern() -> None:
    result = classify_ipv6_path(ipv4_ok=True, ipv6_ok=False, prefer_ipv4_enabled=False)
    assert result["primary_classification"] == "IPV6_PATH_BLACKHOLE"
    joined = " ".join(result["recommended_next_actions"])
    assert "ipv6-path" in joined or "ipv6-prefer-ipv4" in joined


def test_classify_ok_and_degraded() -> None:
    ok = classify_ipv6_path(ipv4_ok=True, ipv6_ok=True, prefer_ipv4_enabled=False)
    assert ok["primary_classification"] == "IPV6_PATH_OK"
    bad = classify_ipv6_path(ipv4_ok=False, ipv6_ok=False, prefer_ipv4_enabled=False)
    assert bad["primary_classification"] == "NETWORK_PATH_DEGRADED"


def test_diagnose_injected_blackhole() -> None:
    payload = diagnose_ipv6_path(
        ipv4_probe={"ok": True, "family": "ipv4", "status": 200},
        ipv6_probe={"ok": False, "family": "ipv6", "error": "timeout"},
        disabled_components=0,
        wifi_ipv6_enabled=True,
    )
    assert payload["classification"] == "IPV6_PATH_BLACKHOLE"
    assert payload["prefer_ipv4_bit_set"] is False
    assert payload["wifi_ipv6_binding_enabled"] is True


def test_prefer_ipv4_dry_run_default_no_write() -> None:
    written: list[int] = []

    def _write(value: int) -> None:
        written.append(value)

    payload = run_prefer_ipv4(
        dry_run=True,
        confirm="",
        diagnose_first=False,
        read_dc=lambda: 0,
        write_dc=_write,
    )
    assert payload["dry_run"] is True
    assert payload["status"] == "preview"
    assert payload["action_allowed"] is False
    assert written == []
    assert payload["disabled_components_planned"] == PREFER_IPV4_BIT
    assert payload["adapter_disable_auto_apply"] is False


def test_prefer_ipv4_blocked_without_token() -> None:
    written: list[int] = []
    payload = run_prefer_ipv4(
        dry_run=False,
        confirm="WRONG",
        diagnose_first=False,
        read_dc=lambda: 0,
        write_dc=written.append,
    )
    assert payload["status"] == "blocked"
    assert payload["action_allowed"] is False
    assert written == []


def test_prefer_ipv4_apply_with_token() -> None:
    written: list[int] = []
    run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))

    with patch("windows_network_toolkit.ipv6_path.is_demo_mode", return_value=False):
        payload = run_prefer_ipv4(
            dry_run=False,
            confirm=CONFIRMATION_PHRASE,
            diagnose_first=False,
            also_flush_dns=True,
            run=run,
            read_dc=lambda: 0,
            write_dc=written.append,
            elevated=True,
        )
    assert payload["status"] == "applied"
    assert payload["action_allowed"] is True
    assert written == [PREFER_IPV4_BIT]
    run.assert_called()


def test_prefer_ipv4_noop_when_already_set() -> None:
    written: list[int] = []
    with patch("windows_network_toolkit.ipv6_path.is_demo_mode", return_value=False):
        payload = run_prefer_ipv4(
            dry_run=False,
            confirm=CONFIRMATION_PHRASE,
            diagnose_first=False,
            read_dc=lambda: PREFER_IPV4_BIT,
            write_dc=written.append,
            elevated=True,
        )
    assert payload["status"] == "noop"
    assert payload["prefer_ipv4_already_set"] is True
    assert written == []


def test_prefer_ipv4_needs_elevation() -> None:
    with patch("windows_network_toolkit.ipv6_path.is_demo_mode", return_value=False):
        payload = run_prefer_ipv4(
            dry_run=False,
            confirm=CONFIRMATION_PHRASE,
            diagnose_first=False,
            read_dc=lambda: 0,
            write_dc=None,
            elevated=False,
        )
    assert payload["status"] == "needs_elevation"
    assert payload["action_allowed"] is False


def test_restore_ipv6_preference_clears_bit() -> None:
    written: list[int] = []
    run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    with patch("windows_network_toolkit.ipv6_path.is_demo_mode", return_value=False):
        payload = run_restore_ipv6_preference(
            dry_run=False,
            confirm=RESTORE_CONFIRMATION_PHRASE,
            run=run,
            read_dc=lambda: PREFER_IPV4_BIT | 0x01,
            write_dc=written.append,
            elevated=True,
        )
    assert payload["status"] == "applied"
    assert written == [0x01]  # other bits preserved
    assert payload["disabled_components_planned"] == 0x01


def test_restore_ipv6_preference_dry_run_and_noop() -> None:
    written: list[int] = []
    preview = run_restore_ipv6_preference(
        dry_run=True,
        confirm="",
        read_dc=lambda: PREFER_IPV4_BIT,
        write_dc=written.append,
        diagnose_first=False,
    )
    assert preview["status"] == "preview"
    assert written == []
    assert "operator_next_step" in preview
    assert preview["operator_next_step"]["kind"] == "verify_before_restore"
    assert "Next:" in preview["message"]

    with patch("windows_network_toolkit.ipv6_path.is_demo_mode", return_value=False):
        noop = run_restore_ipv6_preference(
            dry_run=False,
            confirm=RESTORE_CONFIRMATION_PHRASE,
            read_dc=lambda: 0,
            write_dc=written.append,
            elevated=True,
            diagnose_first=False,
        )
    assert noop["status"] == "noop"
    assert written == []


def test_restore_dry_run_warns_when_ipv6_still_blackholed() -> None:
    fake_diag = {
        "classification": "IPV6_PATH_BLACKHOLE",
        "ipv4_probe": {"ok": True},
        "ipv6_probe": {"ok": False},
    }
    with patch(
        "windows_network_toolkit.ipv6_path.diagnose_ipv6_path",
        return_value=fake_diag,
    ), patch("windows_network_toolkit.ipv6_path.platform.system", return_value="Windows"):
        preview = run_restore_ipv6_preference(
            dry_run=True,
            confirm="",
            read_dc=lambda: PREFER_IPV4_BIT,
            write_dc=lambda _v: None,
            diagnose_first=True,
        )
    assert preview["operator_next_step"]["kind"] == "keep_prefer_ipv4"
    assert "Do NOT" in preview["operator_next_step"]["reason"]
    assert preview["diagnosis"]["classification"] == "IPV6_PATH_BLACKHOLE"


def test_prefer_dry_run_includes_operator_next_step() -> None:
    preview = run_prefer_ipv4(
        dry_run=True,
        confirm="",
        diagnose_first=False,
        read_dc=lambda: 0,
        write_dc=lambda _v: None,
    )
    assert preview["status"] == "preview"
    assert "operator_next_step" in preview
    assert "Next:" in preview["message"]


def test_restore_blocked_without_token() -> None:
    written: list[int] = []
    payload = run_restore_ipv6_preference(
        dry_run=False,
        confirm="WRONG",
        read_dc=lambda: PREFER_IPV4_BIT,
        write_dc=written.append,
        diagnose_first=False,
    )
    assert payload["status"] == "blocked"
    assert written == []
