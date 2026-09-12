"""Browser evidence package tests (fixture-based)."""

from __future__ import annotations

from pathlib import Path

from windows_network_toolkit.browser_evidence import (
    BrowserEvidencePackage,
    load_browser_package_from_fixture,
    summarize_har,
)


def test_load_fixture_package():
    path = Path("tests/fixtures/browser_evidence/sample_package.json")
    pkg = load_browser_package_from_fixture(path)
    assert pkg.navigation_error
    assert "proxy" in pkg.proxy_hints[0].lower() or "PROXY" in (pkg.navigation_error or "")


def test_to_raw_snapshot_includes_browser_package():
    pkg = BrowserEvidencePackage(url="https://example.com", proxy_hints=["test"])
    snap = pkg.to_raw_snapshot()
    assert "browser_package" in snap
    assert "proxy_state" in snap


def test_summarize_har_fixture():
    summary = summarize_har(Path("tests/fixtures/browser_evidence/sample.har.json"))
    assert summary["entries"] == 2
    assert summary["failed"] >= 1
