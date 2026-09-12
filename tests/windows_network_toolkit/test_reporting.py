"""Tests for control incident mapping and reporting exports."""

from __future__ import annotations

import json
from pathlib import Path

from windows_network_toolkit.analytics_pipeline import run_endpoint_analytics_pipeline
from windows_network_toolkit.control_tests import controls_for_incident_class
from windows_network_toolkit.reporting import build_executive_report, export_technology_risk_report

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "analytics_pipeline_fixture.json"


def test_controls_for_incident_class_dead_proxy() -> None:
    ids = controls_for_incident_class("DEAD_PROXY_CONFIG")
    assert "WININET_LOCALHOST_PROXY_HEALTH" in ids


def test_pipeline_includes_risk_scores() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload = run_endpoint_analytics_pipeline(fixture=data)
    assert "risk_scores" in payload
    assert len(payload["risk_scores"]) == len(payload["incidents"])


def test_export_technology_risk_report(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload = run_endpoint_analytics_pipeline(fixture=data)
    paths = export_technology_risk_report(payload, tmp_path)
    assert "executive_report.json" in paths
    assert "risk_scores.json" in paths
    assert Path(paths["executive_report.json"]).is_file()
    executive = json.loads(Path(paths["executive_report.json"]).read_text(encoding="utf-8"))
    assert executive["schema_version"] == "technology_risk_executive_report.v1"


def test_build_executive_report_human_review_flag() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload = run_endpoint_analytics_pipeline(fixture=data)
    report = build_executive_report(payload)
    assert "human_review_recommended" in report["executive_summary"]
