"""Collector facade tests — no live Windows mutations."""

from __future__ import annotations

from unittest.mock import MagicMock

from windows_network_toolkit.collectors.dns_collector import collect_dns_signals
from windows_network_toolkit.collectors.netstat_collector import collect_netstat_signals
from windows_network_toolkit.collectors.proxy_registry_collector import collect_proxy_registry


def test_proxy_registry_collector_with_mock_run() -> None:
    mock = MagicMock()
    mock.return_value = MagicMock(returncode=0, stdout="ProxyEnable    REG_DWORD    0x1", stderr="")

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return mock.return_value

    result = collect_proxy_registry(run=fake_run)
    assert "proxy_enable" in result
    assert result["source"] == "hkcu_internet_settings"


def test_dns_collector_injected() -> None:
    out = collect_dns_signals(dns_ok=True)
    assert out["dns_ok"] is True


def test_netstat_collector_mock() -> None:
    netstat_text = "TCP    127.0.0.1:56186    0.0.0.0:0    LISTENING    1234\n"

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return MagicMock(returncode=0, stdout=netstat_text, stderr="")

    out = collect_netstat_signals(run=fake_run)
    assert out["exit_code"] == 0
    assert isinstance(out["localhost_listen_ports"], list)
