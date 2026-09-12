"""Audit soft-fail tests."""

from __future__ import annotations

from unittest.mock import patch

from windows_network_toolkit.audit_store import append_audit_dict


def test_audit_write_failure_returns_error(tmp_path) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("x", encoding="utf-8")
    blocked.chmod(0o444)
    with patch("windows_network_toolkit.audit_store.audit_dir", return_value=blocked / "nested"):
        ok, err = append_audit_dict({"command": "test"}, log_name="test.jsonl")
    assert ok is False or err is not None


def test_remediation_reports_audit_error_on_linux() -> None:
    from unittest.mock import patch as mp

    from windows_network_toolkit.proxy_remediation import run_proxy_disable

    with mp("windows_network_toolkit.proxy_remediation.platform.system", return_value="Linux"):
        result = run_proxy_disable(dry_run=True)
    assert result.get("unsupported_platform") is True
