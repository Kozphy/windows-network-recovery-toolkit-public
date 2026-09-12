"""CLI smoke tests for proxy diagnostic commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from windows_network_toolkit import cli
from windows_network_toolkit.audit.report_generator import generate_erp_report
from windows_network_toolkit.diagnostics.proxy.runner import (
    run_full_incident_report,
    run_proxy_timeline,
)

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "erp"


def _attr_fixture() -> dict:
    return json.loads((FIXTURES / "attribution_dead_proxy.json").read_text(encoding="utf-8"))


def _proof_fixture() -> dict:
    return json.loads((FIXTURES / "proof_local_proxy_failure.json").read_text(encoding="utf-8"))


def test_proxy_timeline_with_inject() -> None:
    result = run_proxy_timeline(
        "https://example.com/",
        inject_attribution=_attr_fixture(),
        inject_proof=_proof_fixture(),
    )
    assert result["incident_id"]
    assert len(result["timeline"]) >= 3
    assert result["remediation_preview"]["dry_run"] is True


def test_full_incident_report_fixture_sections() -> None:
    package = run_full_incident_report(
        "https://example.com/",
        inject_attribution=_attr_fixture(),
        inject_proof=_proof_fixture(),
    )
    md = generate_erp_report(package, fmt="markdown")
    assert "Executive Summary" in md
    assert "Chain of Custody" in md
    assert "Rollback Plan" in md


def test_cli_report_from_fixture(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    fixture = repo / "windows_network_toolkit" / "examples" / "proxy_drift_incident.jsonl"
    rc = cli.main(["report", str(fixture), "--format", "json"])
    assert rc == 0


def test_cli_audit_verify_empty_chain(tmp_path: Path) -> None:
    from src.platform_core.audit.writer import append_audit, reset_chain_for_tests

    reset_chain_for_tests()
    path = tmp_path / "audit.jsonl"
    append_audit("event_received", incident_id="i1", path=path)
    append_audit("policy_evaluated", incident_id="i1", path=path)
    rc = cli.main(["audit", "verify", str(path)])
    assert rc == 0


def test_cli_bad_gateway_help_exits() -> None:
    with patch.object(
        cli,
        "cmd_bad_gateway_diagnose",
        return_value=0,
    ):
        rc = cli.main(["bad-gateway-diagnose", "--url", "https://example.com", "--summary-only"])
    assert rc == 0
