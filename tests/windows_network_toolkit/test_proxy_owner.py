"""Proxy owner detection tests."""

from __future__ import annotations

from windows_network_toolkit.proxy_owner import detect_proxy_owner


def test_no_listener_fixture() -> None:
    payload = detect_proxy_owner(
        inject={
            "timestamp_utc": "2026-06-11T04:31:31Z",
            "proxy_server": "127.0.0.1:59081",
            "localhost_port": 59081,
            "listener_found": False,
            "process": None,
            "errors": [],
        }
    )
    assert payload["listener_found"] is False
    assert payload["process"] is None


def test_listener_exists_fixture() -> None:
    payload = detect_proxy_owner(
        inject={
            "timestamp_utc": "2026-06-11T04:31:31Z",
            "proxy_server": "127.0.0.1:8080",
            "localhost_port": 8080,
            "listener_found": True,
            "process": {
                "pid": 4242,
                "name": "node.exe",
                "exe_path": "C:\\node.exe",
                "cmdline": "node dev-server.js",
                "username": "user",
            },
            "errors": [],
        }
    )
    assert payload["listener_found"] is True
    assert payload["process"]["pid"] == 4242
