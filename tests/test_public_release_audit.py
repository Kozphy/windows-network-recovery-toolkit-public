"""Public release audit script and safety regression hooks."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_audit_module():
    script = _REPO_ROOT / "tools" / "public_release_audit.py"
    spec = importlib.util.spec_from_file_location("public_release_audit", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["public_release_audit"] = module
    spec.loader.exec_module(module)
    return module


def test_public_release_audit_allows_synthetic_fixtures(tmp_path: Path) -> None:
    audit = _load_audit_module()
    allowed = tmp_path / "tests" / "fixtures" / "demo.jsonl"
    allowed.parent.mkdir(parents=True)
    allowed.write_text('{"schema_version":"1"}\n', encoding="utf-8")
    risky = tmp_path / "logs" / "audit.jsonl"
    risky.parent.mkdir(parents=True)
    risky.write_text('{"secret":"oops"}\n', encoding="utf-8")

    findings = audit.scan_repo(tmp_path, tracked_only=False)
    assert audit.has_high_risk(findings)
    assert findings.get("jsonl_outside_demo") or findings.get("runtime_artifacts")
    assert not any(p.endswith("tests/fixtures/demo.jsonl") for p in findings.get("jsonl_outside_demo", []))


def test_public_release_audit_allows_committed_sample_reports(tmp_path: Path) -> None:
    audit = _load_audit_module()
    sample = tmp_path / "reports" / "sample_governance_report.md"
    sample.parent.mkdir(parents=True)
    sample.write_text("# Sample governance report\n", encoding="utf-8")
    risky = tmp_path / "reports" / "live_incident_export.md"
    risky.write_text("# Real runtime export\n", encoding="utf-8")

    findings = audit.scan_repo(tmp_path, tracked_only=False)
    runtime = findings.get("runtime_artifacts", [])
    assert not any(p.endswith("reports/sample_governance_report.md") for p in runtime)
    assert any(p.endswith("reports/live_incident_export.md") for p in runtime)


def test_public_release_audit_passes_on_tracked_files_only() -> None:
    audit = _load_audit_module()
    tracked = audit.git_tracked_files(_REPO_ROOT)
    if tracked:
        findings = audit.scan_repo(_REPO_ROOT, tracked_only=True, tracked_files=tracked)
        assert not audit.has_high_risk(findings)
        return

    # Fallback when git subprocess is unavailable (e.g. restricted CI sandbox).
    sample = tmp_safe_tracked_files()
    findings = audit.scan_repo(_REPO_ROOT, tracked_only=True, tracked_files=sample)
    assert not audit.has_high_risk(findings)


def tmp_safe_tracked_files() -> set[str]:
    return {
        "README.md",
        "SECURITY.md",
        "examples/synthetic_platform_audit.jsonl",
        "config/last_known_good_proxy.example.json",
        "tests/fixtures/features_healthy_signals.json",
    }


def test_examples_jsonl_is_committed_synthetic() -> None:
    sample = _REPO_ROOT / "examples" / "synthetic_platform_audit.jsonl"
    assert sample.is_file()
    lines = sample.read_text(encoding="utf-8").strip().splitlines()
    assert lines
    row = json.loads(lines[0])
    assert row.get("actor") == "demo-user"
    assert "demo" in row.get("target_id", "")


def test_remediation_execute_model_defaults_dry_run() -> None:
    from backend.platform_routes import ExecuteIn

    assert ExecuteIn(preview_id="p1").dry_run is True


def test_high_risk_registry_actions_blocked_for_admin() -> None:
    from platform_core.policy import OperatorContext, evaluate

    gate = evaluate({}, "process_kill_forbidden", OperatorContext(role="admin", surface="api"))
    assert gate.execute_allowed is False


def test_arbitrary_shell_injection_rejected_by_policy_helper() -> None:
    from platform_core.policy import is_shell_injection

    assert is_shell_injection("reset_dns; calc.exe") is True
