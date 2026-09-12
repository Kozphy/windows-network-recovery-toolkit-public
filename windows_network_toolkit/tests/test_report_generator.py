"""Report generator tests."""

from __future__ import annotations

from windows_network_toolkit.audit.report_generator import generate_report


def test_report_markdown_sections() -> None:
    text = generate_report(
        timeline=[{"timestamp": "2026-06-09T10:01:00Z", "signal": "PROXY_ENABLED", "observed_value": "1", "severity": "medium"}],
        decision={"incident_type": "WININET_PROXY_DRIFT", "confidence": 0.88, "risk_level": "medium"},
        policy={"outcome": "ALLOW_WITH_CONFIRMATION", "dry_run": True},
        remediation={"previews": [], "rollback_plan": {}},
        fmt="markdown",
    )
    assert "Executive Summary" in text
    assert "Audit Trail" in text
    assert "WinINET proxy drift" in text


def test_report_json() -> None:
    text = generate_report(
        timeline=[],
        decision={"incident_type": "NO_PROXY", "confidence": 0.5, "risk_level": "low"},
        policy={"outcome": "ALLOW_PREVIEW"},
        remediation={},
        fmt="json",
    )
    assert '"executive_summary"' in text
