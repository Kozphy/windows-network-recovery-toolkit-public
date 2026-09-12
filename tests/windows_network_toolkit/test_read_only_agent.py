"""Tests for read-only WNRT agent (Phase 2)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from windows_network_toolkit.agent.read_only import (
    FORBIDDEN_REMEDIATION_MODULES,
    READ_ONLY_POLICY_BOUNDARY,
    build_evidence_event,
    collect_once,
    get_health_status,
    get_spool_status,
    run_agent_loop,
)
from windows_network_toolkit.cli import main
from windows_network_toolkit.safety import BLOCKED_ACTIONS

FIXTURE_BUNDLE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "agent" / "sample_evidence_bundle.json"
)


def test_build_evidence_event_from_fixture() -> None:
    event = build_evidence_event(
        endpoint_id="ep-test-001",
        fixture_path=FIXTURE_BUNDLE,
    )
    assert event["read_only"] is True
    assert event["automatic_repair"] is False
    assert event["remediation_executed"] is False
    assert event["policy_boundary"] == READ_ONLY_POLICY_BOUNDARY
    assert set(event["blocked_actions"]) == set(BLOCKED_ACTIONS)
    assert event["evidence"]["platform_support_level"] == "FULL"
    assert event["limitations"]


def test_collect_once_appends_spool(tmp_path: Path) -> None:
    spool = tmp_path / "agent-spool.jsonl"
    result = collect_once(spool_path=spool, fixture_path=FIXTURE_BUNDLE, endpoint_id="ep-spool-1")
    assert result["read_only"] is True
    assert result["automatic_repair"] is False
    assert spool.is_file()
    lines = spool.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["event_kind"] == "agent_evidence_collected"
    assert row["endpoint_id"] == "ep-spool-1"


def test_run_agent_loop_max_cycles(tmp_path: Path) -> None:
    spool = tmp_path / "loop.jsonl"
    code = run_agent_loop(
        spool_path=spool,
        fixture_path=FIXTURE_BUNDLE,
        interval_seconds=5.0,
        max_cycles=2,
    )
    assert code == 0
    assert len(spool.read_text(encoding="utf-8").strip().splitlines()) == 2


def test_get_health_status_idle(tmp_path: Path) -> None:
    spool = tmp_path / "empty.jsonl"
    health = get_health_status(spool_path=spool)
    assert health["agent_mode"] == "read_only"
    assert health["read_only"] is True
    assert health["automatic_repair"] is False
    assert health["health"] == "idle"
    assert health["spool"]["event_count"] == 0


def test_get_spool_status_after_collect(tmp_path: Path) -> None:
    spool = tmp_path / "status.jsonl"
    collect_once(spool_path=spool, fixture_path=FIXTURE_BUNDLE, endpoint_id="ep-st")
    status = get_spool_status(spool_path=spool)
    assert status["event_count"] == 1
    assert status["read_only"] is True
    assert status["last_event_kind"] == "agent_evidence_collected"


def test_agent_does_not_call_remediation_modules(tmp_path: Path) -> None:
    """Agent path must not import or invoke remediation execute modules."""
    spool = tmp_path / "safe.jsonl"
    stubs = {name: MagicMock() for name in FORBIDDEN_REMEDIATION_MODULES}
    with patch.dict(sys.modules, stubs):
        with patch("subprocess.run") as subprocess_run:
            with patch("subprocess.Popen") as subprocess_popen:
                collect_once(spool_path=spool, fixture_path=FIXTURE_BUNDLE, endpoint_id="ep-safe")
                subprocess_run.assert_not_called()
                subprocess_popen.assert_not_called()
        for name in FORBIDDEN_REMEDIATION_MODULES:
            mod = sys.modules.get(name)
            if mod is not None and hasattr(mod, "apply_remediation"):
                mod.apply_remediation.assert_not_called()


def test_collect_once_live_windows_uses_evidence_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool = tmp_path / "live.jsonl"
    monkeypatch.setattr(
        "windows_network_toolkit.agent.read_only.collect_endpoint_evidence",
        lambda os_family=None: {
            "os_family": "windows",
            "platform_support_level": "FULL",
            "collector_id": "test",
            "observations": [{"signal_name": "os_family", "value": "windows", "source": "test"}],
            "limitations": ["test"],
            "live_remediation_supported": True,
        },
    )
    collect_once(spool_path=spool, os_family="windows", endpoint_id="ep-live")
    row = json.loads(spool.read_text(encoding="utf-8").strip())
    assert row["platform_support_level"] == "FULL"
    assert row["read_only"] is True


def test_cli_agent_once_with_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    spool = tmp_path / "cli-spool.jsonl"
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "agent",
            "once",
            "--fixture",
            str(FIXTURE_BUNDLE.resolve()),
            "--spool",
            str(spool),
        ],
        prog="test-toolkit",
    )
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["read_only"] is True
    assert spool.is_file()


def test_cli_agent_spool_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spool = tmp_path / "cli-status.jsonl"
    collect_once(spool_path=spool, fixture_path=FIXTURE_BUNDLE, endpoint_id="ep-cli")
    code = main(["agent", "spool-status", "--spool", str(spool)], prog="test-toolkit")
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_count"] == 1


def test_probe_backend_health_optional() -> None:
    with patch("httpx.get") as get:
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"status": "ok"}
        get.return_value = response
        from windows_network_toolkit.agent.read_only import probe_backend_health

        payload = probe_backend_health("http://127.0.0.1:8000")
        assert payload is not None
        assert payload["reachable"] is True
        get.assert_called_once()
