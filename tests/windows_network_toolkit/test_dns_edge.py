"""Tests for DNS/Edge ERR_NAME_NOT_RESOLVED diagnose and gated fix."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from windows_network_toolkit.dns_edge import (
    CONFIRMATION_PHRASE,
    classify_dns_edge,
    diagnose_dns_edge,
    run_dns_edge_fix,
)
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, is_blocked_action


def test_dns_edge_token_registered() -> None:
    assert CONFIRMATION_TOKENS["FIX_ERR_NAME_NOT_RESOLVED"] == "FIX_ERR_NAME_NOT_RESOLVED"
    assert CONFIRMATION_PHRASE == "FIX_ERR_NAME_NOT_RESOLVED"
    assert is_blocked_action("ADAPTER_DISABLE")


def test_classify_resolve_failed() -> None:
    result = classify_dns_edge(
        resolve_ok_count=0,
        resolve_total=3,
        wifi={"dns_servers": ["192.168.68.1"]},
        edge_policy={"dns_over_https_mode": None, "builtin_dns_client_enabled": None},
        mismatch={},
    )
    assert result["primary_classification"] == "DNS_RESOLVE_FAILED"


def test_classify_err_name_likely_router_first() -> None:
    result = classify_dns_edge(
        resolve_ok_count=2,
        resolve_total=3,
        wifi={"dns_servers": ["192.168.68.1", "1.1.1.1"]},
        edge_policy={"dns_over_https_mode": None, "builtin_dns_client_enabled": None},
        mismatch={"primary_off_subnet": False},
    )
    assert result["primary_classification"] == "ERR_NAME_NOT_RESOLVED_LIKELY"
    joined = " ".join(result["recommended_next_actions"])
    assert "dns-edge-fix" in joined


def test_classify_ok() -> None:
    result = classify_dns_edge(
        resolve_ok_count=3,
        resolve_total=3,
        wifi={"dns_servers": ["1.1.1.1", "8.8.8.8", "192.168.68.1"]},
        edge_policy={"dns_over_https_mode": "off", "builtin_dns_client_enabled": 0},
        mismatch={},
    )
    assert result["primary_classification"] == "DNS_EDGE_OK"


def test_diagnose_injected_likely() -> None:
    payload = diagnose_dns_edge(
        wifi={
            "interface_alias": "Wi-Fi",
            "ipv4": "192.168.68.10",
            "gateway": "192.168.68.1",
            "dns_servers": ["192.168.68.1"],
            "error": None,
        },
        edge_policy={"dns_over_https_mode": None, "builtin_dns_client_enabled": None},
        resolves=[
            {"host": "www.google.com", "ok": True, "addresses": ["1.2.3.4"], "error": None},
        ],
    )
    assert payload["classification"] == "ERR_NAME_NOT_RESOLVED_LIKELY"
    assert payload["planned_dns_servers"][:2] == ["1.1.1.1", "8.8.8.8"]
    assert "192.168.68.1" in payload["planned_dns_servers"]


def test_fix_dry_run_default_no_write() -> None:
    written_dns: list[list[str]] = []
    edge_writes: list[tuple[str, int]] = []

    payload = run_dns_edge_fix(
        dry_run=True,
        confirm="",
        diagnose_first=False,
        read_wifi=lambda: {
            "dns_servers": ["192.168.68.1"],
            "gateway": "192.168.68.1",
            "ipv4": "192.168.68.10",
        },
        write_dns=written_dns.append,
        write_edge=lambda doh_mode="off", builtin_enabled=0: edge_writes.append(
            (doh_mode, builtin_enabled)
        ),
        flush=lambda: True,
        elevated=True,
    )
    assert payload["dry_run"] is True
    assert payload["status"] == "preview"
    assert payload["action_allowed"] is False
    assert written_dns == []
    assert edge_writes == []
    assert payload["dns_servers_planned"][:2] == ["1.1.1.1", "8.8.8.8"]


def test_fix_blocked_without_token() -> None:
    written_dns: list[list[str]] = []
    payload = run_dns_edge_fix(
        dry_run=False,
        confirm="WRONG",
        diagnose_first=False,
        read_wifi=lambda: {"dns_servers": ["192.168.68.1"], "gateway": "192.168.68.1"},
        write_dns=written_dns.append,
        elevated=True,
    )
    assert payload["status"] == "blocked"
    assert payload["action_allowed"] is False
    assert written_dns == []


def test_fix_needs_elevation() -> None:
    written_dns: list[list[str]] = []
    with patch("windows_network_toolkit.dns_edge.is_demo_mode", return_value=False):
        payload = run_dns_edge_fix(
            dry_run=False,
            confirm=CONFIRMATION_PHRASE,
            diagnose_first=False,
            read_wifi=lambda: {"dns_servers": ["192.168.68.1"], "gateway": "192.168.68.1"},
            # write_dns left None so elevation gate applies
            elevated=False,
            require_elevation=True,
        )
    assert payload["status"] == "needs_elevation"
    assert payload["action_allowed"] is False
    assert written_dns == []


def test_fix_apply_with_token() -> None:
    written_dns: list[list[str]] = []
    edge_writes: list[tuple[str, int]] = []
    restarts: list[bool] = []

    with patch("windows_network_toolkit.dns_edge.is_demo_mode", return_value=False):
        payload = run_dns_edge_fix(
            dry_run=False,
            confirm=CONFIRMATION_PHRASE,
            diagnose_first=False,
            restart_edge=True,
            read_wifi=lambda: {
                "dns_servers": ["192.168.68.1"],
                "gateway": "192.168.68.1",
                "ipv4": "192.168.68.10",
            },
            write_dns=written_dns.append,
            write_edge=lambda doh_mode="off", builtin_enabled=0: edge_writes.append(
                (doh_mode, builtin_enabled)
            ),
            flush=lambda: True,
            restart=lambda: restarts.append(True) or {"restarted": True, "method": "taskkill"},
            elevated=True,
        )
    assert payload["status"] == "applied"
    assert payload["action_allowed"] is True
    assert written_dns == [["1.1.1.1", "8.8.8.8", "192.168.68.1"]]
    assert edge_writes == [("off", 0)]
    assert restarts == [True]
    assert payload["dns_flushed"] is True
    assert payload["edge_restart"]["restarted"] is True


def test_cli_dns_edge_handlers_exist() -> None:
    from windows_network_toolkit import cli as cli_mod

    assert callable(cli_mod.cmd_dns_edge_status)
    assert callable(cli_mod.cmd_dns_edge_fix)


def test_cli_dns_edge_status_injected(capsys) -> None:
    from windows_network_toolkit.cli import cmd_dns_edge_status

    args = MagicMock()
    args.interface = "Wi-Fi"
    with patch(
        "windows_network_toolkit.dns_edge.diagnose_dns_edge",
        return_value={"classification": "DNS_EDGE_OK", "limitations": []},
    ):
        code = cmd_dns_edge_status(args)
    assert code == 0
    assert "DNS_EDGE_OK" in capsys.readouterr().out
