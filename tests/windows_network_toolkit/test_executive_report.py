"""Executive report and wording safety tests."""

from __future__ import annotations

from pathlib import Path

from windows_network_toolkit.diagnostics.lan_privacy.executive_report import (
    build_executive_report,
    render_executive_markdown,
)
from windows_network_toolkit.diagnostics.lan_privacy.report import (
    validate_report_wording,
    render_lan_privacy_markdown,
    build_lan_privacy_report,
)
from windows_network_toolkit.diagnostics.lan_privacy.runner import run_executive_report_pipeline

REPO = Path(__file__).resolve().parents[2]
FORBIDDEN = ["confirmed spying", "confirmed malware", "confirmed data theft"]


def test_executive_report_sections():
    repo = REPO / "examples" / "lan" / "executive_bundle.json"
    result = run_executive_report_pipeline(load_bundle_path(repo))
    report = result["report"]
    assert report.get("executive_summary")
    assert report.get("evidence_tier")
    assert report.get("what_tool_cannot_prove")
    assert report.get("control_gaps") is not None


def load_bundle_path(path: Path) -> dict:
    from windows_network_toolkit.diagnostics.lan_privacy.runner import load_bundle

    return load_bundle(path)


def test_executive_markdown_wording_safe():
    repo = REPO / "examples" / "lan" / "executive_bundle.json"
    result = run_executive_report_pipeline(load_bundle_path(repo))
    md = render_executive_markdown(result["report"])
    for phrase in FORBIDDEN:
        assert phrase not in md.lower()
    assert "cannot confirm data exfiltration" in md.lower()


def test_lan_privacy_report_wording():
    report = build_lan_privacy_report(
        inventory={"devices": []},
        observations=[],
        classification={
            "primary_classification": "NORMAL_DISCOVERY",
            "limitations": [],
            "reasoning": "test",
            "highest_evidence_source": "HOST_LEVEL_OBSERVATION",
        },
        risk_score={
            "numeric_score": 10,
            "risk_level": "LOW",
            "evidence_tier": "T0_OBSERVATION",
            "components": {},
            "explanation": "observed local network discovery activity",
            "limitations": ["cannot confirm data exfiltration from Windows host telemetry alone"],
            "evidence_sources_present": ["HOST_LEVEL_OBSERVATION"],
        },
    )
    md = render_lan_privacy_markdown(report)
    violations = validate_report_wording(md)
    assert not violations
    assert "observed local network discovery activity" in md.lower()
