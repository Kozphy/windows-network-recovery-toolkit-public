"""Deterministic tests for monitoring dashboard collectors, watcher, and Procmon import."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_network_toolkit.collectors.procmon_import import (
    ProcmonImportError,
    import_procmon_csv,
    import_procmon_csv_summary,
)
from windows_network_toolkit.collectors.proxy_listener import check_local_proxy_listener
from windows_network_toolkit.collectors.proxy_state import (
    collect_dashboard_proxy_state,
    parse_localhost_proxy_server,
)
from windows_network_toolkit.collectors.proxy_watcher import ProxyWatcher
from windows_network_toolkit.dashboard.config import DashboardConfig
from windows_network_toolkit.dashboard.state import DashboardRuntime
from windows_network_toolkit.storage.event_store import EvidenceEventStore


def test_registry_values_present() -> None:
    state = collect_dashboard_proxy_state(
        inject={
            "proxy_enable": 1,
            "proxy_server": "127.0.0.1:60505",
            "auto_config_url": "",
            "auto_detect": 0,
            "proxy_override": "<local>",
            "source": "inject",
        }
    )
    assert state.is_enabled
    assert state.proxy_server == "127.0.0.1:60505"
    assert state.localhost_port == 60505
    assert state.is_localhost_proxy


def test_registry_values_missing() -> None:
    state = collect_dashboard_proxy_state(inject={})
    assert state.proxy_enable is None
    assert state.proxy_server is None
    assert state.auto_config_url is None
    assert not state.is_enabled


def test_localhost_proxy_parsing_ipv4_ipv6() -> None:
    assert parse_localhost_proxy_server("127.0.0.1:60505")[0] is True
    assert parse_localhost_proxy_server("localhost:60505")[2] == 60505
    is_local, host, port = parse_localhost_proxy_server("[::1]:60505")
    assert is_local and host == "::1" and port == 60505
    assert parse_localhost_proxy_server("proxy.corp:8080")[0] is False


def test_listener_present_and_missing() -> None:
    present = check_local_proxy_listener(
        60505,
        inject={
            "listener_present": True,
            "listener_pid": 42,
            "listener_process_name": "node.exe",
            "listener_address": "127.0.0.1",
            "listener_port": 60505,
        },
    )
    assert present.listener_present and present.listener_pid == 42
    missing = check_local_proxy_listener(60505, inject={"listener_present": False, "listener_port": 60505})
    assert not missing.listener_present


def test_listener_access_denied() -> None:
    def boom() -> list:
        raise PermissionError("Access is denied")

    result = check_local_proxy_listener(1, connections_fn=boom)
    assert result.access_denied
    assert not result.listener_present


def test_state_change_detection_and_unchanged_suppression(tmp_path: Path) -> None:
    store = EvidenceEventStore(max_visible=50, storage_path=tmp_path / "e.jsonl", persist=True)
    states = [
        {
            "proxy_enable": 0,
            "proxy_server": None,
            "auto_config_url": None,
            "auto_detect": 0,
        },
        {
            "proxy_enable": 0,
            "proxy_server": None,
            "auto_config_url": None,
            "auto_detect": 0,
        },
        {
            "proxy_enable": 1,
            "proxy_server": "127.0.0.1:60505",
            "auto_config_url": None,
            "auto_detect": 0,
        },
    ]
    idx = {"i": 0}

    def collect():
        raw = states[min(idx["i"], len(states) - 1)]
        idx["i"] += 1
        return collect_dashboard_proxy_state(inject=raw)

    def listener(port):
        return check_local_proxy_listener(port, inject={"listener_present": False, "listener_port": port})

    watcher = ProxyWatcher(store, interval_seconds=0.2, collect_state=collect, check_listener=listener)
    e1 = watcher.poll_once()
    e2 = watcher.poll_once()
    e3 = watcher.poll_once()
    assert e1 is not None  # baseline
    assert e2 is None  # unchanged suppressed
    assert e3 is not None  # change
    assert e3.classification
    assert e3.proof_tier
    assert store.recent()


def test_watcher_clean_shutdown() -> None:
    store = EvidenceEventStore(max_visible=20, persist=False)
    watcher = ProxyWatcher(
        store,
        interval_seconds=0.2,
        collect_state=lambda: collect_dashboard_proxy_state(inject={"proxy_enable": 0}),
        check_listener=lambda port: check_local_proxy_listener(None),
        sleep_fn=lambda _s: None,
    )
    watcher.start()
    watcher.stop(timeout=2.0)
    assert watcher.status == "stopped"


def test_procmon_csv_parsing(tmp_path: Path) -> None:
    csv_path = tmp_path / "capture.csv"
    csv_path.write_text(
        "Time of Day,Process Name,PID,Operation,Path,Result,Detail\n"
        "10:00:00.0,node.exe,123,RegSetValue,"
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable,"
        "SUCCESS,Type: REG_DWORD, Length: 4, Data: 1\n"
        "10:00:01.0,chrome.exe,9,RegQueryValue,"
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer,"
        "SUCCESS,x\n",
        encoding="utf-8",
    )
    events = import_procmon_csv(csv_path)
    assert len(events) == 1
    assert events[0].source == "procmon_csv"
    assert events[0].data["process_name"] == "node.exe"
    summary = import_procmon_csv_summary(csv_path)
    assert summary["events_imported"] == 1


def test_malformed_procmon_csv(tmp_path: Path) -> None:
    bad = tmp_path / "bad.csv"
    bad.write_text("foo,bar\n1,2\n", encoding="utf-8")
    with pytest.raises(ProcmonImportError) as exc:
        import_procmon_csv(bad)
    assert exc.value.code == "MISSING_COLUMNS"
    with pytest.raises(ProcmonImportError):
        import_procmon_csv(tmp_path / "missing.csv")


def test_dashboard_config_rejects_wildcard_bind() -> None:
    with pytest.raises(ValueError):
        DashboardConfig(host="0.0.0.0").validate()


def test_dashboard_startup_smoke() -> None:
    cfg = DashboardConfig(host="127.0.0.1", port=8765, watch_interval=1.0)
    cfg.validate()
    store = EvidenceEventStore(persist=False)
    from windows_network_toolkit.collectors.proxy_watcher import ProxyWatcher

    watcher = ProxyWatcher(
        store,
        collect_state=lambda: collect_dashboard_proxy_state(inject={"proxy_enable": 0}),
        check_listener=lambda port: check_local_proxy_listener(None),
    )
    runtime = DashboardRuntime(config=cfg, store=store, watcher=watcher)
    payload = runtime.overview_payload()
    assert "collector_status" in payload
    assert runtime.ui_notes
    assert "does not prove human intent" in " ".join(runtime.ui_notes)


def test_cli_procmon_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from windows_network_toolkit.cli import main

    csv_path = tmp_path / "c.csv"
    csv_path.write_text(
        "Time of Day,Process Name,PID,Operation,Path,Result,Detail\n"
        "10:00:00.0,node.exe,1,RegSetValue,"
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer,"
        "SUCCESS,127.0.0.1:1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    rc = main(["procmon-import", str(csv_path)])
    assert rc == 0


def test_event_store_clear_ui_does_not_delete_file(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = EvidenceEventStore(max_visible=10, storage_path=path, persist=True)
    watcher = ProxyWatcher(
        store,
        collect_state=lambda: collect_dashboard_proxy_state(
            inject={"proxy_enable": 1, "proxy_server": "127.0.0.1:1"}
        ),
        check_listener=lambda port: check_local_proxy_listener(
            port, inject={"listener_present": False, "listener_port": port}
        ),
    )
    watcher.poll_once()
    assert path.is_file()
    before = path.read_text(encoding="utf-8")
    store.clear_ui_view()
    assert store.recent() == []
    assert path.read_text(encoding="utf-8") == before
    assert json.loads(before.splitlines()[0])["event_id"]
