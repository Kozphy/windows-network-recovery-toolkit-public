"""Browser-profile differential diagnostics — fixture-first tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_network_toolkit.diagnostics.browser_profile.adapters.chromium import domain_matches
from windows_network_toolkit.diagnostics.browser_profile.classifier import classify_browser_diff
from windows_network_toolkit.diagnostics.browser_profile.har_compare import compare_hars
from windows_network_toolkit.diagnostics.browser_profile.models import (
    BrowserDiffClassification,
    RawNetworkBaseline,
)
from windows_network_toolkit.diagnostics.browser_profile.os_baseline import (
    collect_raw_network_baseline,
)
from windows_network_toolkit.diagnostics.browser_profile.redaction import redact_har, redact_url
from windows_network_toolkit.diagnostics.browser_profile.repair import (
    assert_domain_guard,
    build_repair_preview,
)
from windows_network_toolkit.diagnostics.browser_profile.runner import (
    run_browser_diff,
    run_repair_apply,
)

FIX = Path("tests/fixtures/browser_profile")


def _raw_ok(**kwargs):
    base = dict(
        target_url="https://www.104.com.tw/",
        dns_ok=True,
        tcp_ok=True,
        tls_ok=True,
        http_status=200,
        direct_probe_ok=True,
        system_proxy_probe_ok=True,
        wininet_proxy_enable=0,
        winhttp_proxy="direct",
    )
    base.update(kwargs)
    return RawNetworkBaseline.model_validate(base)


def test_fixture_browser_diff_104_case() -> None:
    result = run_browser_diff(
        "https://www.104.com.tw/",
        browser="edge",
        fixture=FIX / "104_profile_fail.json",
    )
    assert result.classification == BrowserDiffClassification.OS_NETWORK_OK_BROWSER_PROFILE_FAIL
    assert result.confidence >= 0.9
    assert "DNS resolution succeeded." in result.evidence
    assert result.audit_id


def test_har_redirect_loop_classifies_auth_or_cookie() -> None:
    normal = json.loads((FIX / "normal_redirect_loop.har.json").read_text(encoding="utf-8"))
    private = json.loads((FIX / "private_ok.har.json").read_text(encoding="utf-8"))
    har = compare_hars(normal, private)
    assert har.private_ok is True
    assert har.normal_ok is False
    assert har.auth_challenge_loop_hint is True
    # secrets redacted
    assert "SUPERSECRET" not in json.dumps(har.model_dump())
    cls, conf, _lvl, ev, *_rest = classify_browser_diff(
        raw=_raw_ok(),
        har=har,
        site_state={"domain": "www.104.com.tw", "cookie_count": 3},
        extensions=[],
        network_prefs=None,
        policies=None,
    )
    assert cls in {
        BrowserDiffClassification.AUTHENTICATION_REDIRECT_LOOP,
        BrowserDiffClassification.SITE_DATA_OR_COOKIE_LOOP,
        BrowserDiffClassification.OS_NETWORK_OK_BROWSER_PROFILE_FAIL,
    }
    assert conf >= 0.7


def test_har_secret_redaction() -> None:
    har = json.loads((FIX / "normal_redirect_loop.har.json").read_text(encoding="utf-8"))
    redacted, notes = redact_har(har)
    blob = json.dumps(redacted)
    assert "SUPERSECRET" not in blob
    assert "SECRET_TOKEN" not in blob
    assert "SECRETSESSION" not in blob
    assert any("Cookie" in n or "header:Cookie" in n or "header:cookie" in n.lower() for n in notes) or notes
    url, qnotes = redact_url("https://x.test/?token=abc&q=1")
    assert "abc" not in url
    assert qnotes


def test_extension_blocking_classification() -> None:
    normal = json.loads((FIX / "normal_blocked.har.json").read_text(encoding="utf-8"))
    private = json.loads((FIX / "private_ok.har.json").read_text(encoding="utf-8"))
    har = compare_hars(normal, private)
    assert har.blocked_in_normal
    cls, *_ = classify_browser_diff(
        raw=_raw_ok(),
        har=har,
        site_state=None,
        extensions=[],
        network_prefs=None,
        policies=None,
    )
    assert cls == BrowserDiffClassification.EXTENSION_BLOCKING


def test_raw_network_failure_class() -> None:
    har = compare_hars(
        {"log": {"entries": []}},
        {"log": {"entries": []}},
    )
    cls, conf, *_ = classify_browser_diff(
        raw=_raw_ok(dns_ok=False, tcp_ok=False, tls_ok=False, direct_probe_ok=False, http_status=None),
        har=har,
        site_state=None,
        extensions=[],
        network_prefs=None,
        policies=None,
    )
    assert cls == BrowserDiffClassification.RAW_NETWORK_FAILURE
    assert conf >= 0.8


def test_site_server_failure_5xx() -> None:
    cls, *_ = classify_browser_diff(
        raw=_raw_ok(direct_probe_ok=False, http_status=502, dns_ok=True, tcp_ok=True, tls_ok=True),
        har=None,
        site_state=None,
        extensions=[],
        network_prefs=None,
        policies=None,
    )
    assert cls == BrowserDiffClassification.SITE_SERVER_FAILURE


def test_both_fail_and_both_ok() -> None:
    fail = {
        "log": {
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://x.test/", "headers": []},
                    "response": {"status": 500, "headers": []},
                }
            ]
        }
    }
    ok = json.loads((FIX / "private_ok.har.json").read_text(encoding="utf-8"))
    har_fail = compare_hars(fail, fail)
    cls, *_ = classify_browser_diff(raw=_raw_ok(), har=har_fail, site_state=None, extensions=[], network_prefs=None, policies=None)
    assert cls == BrowserDiffClassification.NO_DIFF_BOTH_FAIL
    har_ok = compare_hars(ok, ok)
    cls2, *_ = classify_browser_diff(raw=_raw_ok(), har=har_ok, site_state=None, extensions=[], network_prefs=None, policies=None)
    assert cls2 == BrowserDiffClassification.NO_DIFF_BOTH_OK


def test_malformed_har_compare_empty() -> None:
    har = compare_hars({"log": {}}, {"not": "har"})
    assert har.normal_entry_count == 0
    assert har.private_entry_count == 0


def test_domain_guard_prevents_unrelated() -> None:
    assert domain_matches("www.104.com.tw", ".104.com.tw")
    assert not domain_matches("evil.example", "104.com.tw")
    assert assert_domain_guard("104.com.tw", "www.104.com.tw")
    assert not assert_domain_guard("104.com.tw", "linkedin.com")


def test_repair_preview_is_dry_run() -> None:
    preview = build_repair_preview("104.com.tw", browser="edge", has_cookies=True)
    assert preview.dry_run is True
    assert preview.requires_confirm_token == "BROWSER_SITE_REPAIR_APPLY"
    assert any(a["id"] == "delete_domain_cookies" for a in preview.actions)


def test_repair_apply_requires_confirm() -> None:
    blocked = run_repair_apply("brp-x", confirm="")
    assert blocked["decision"] == "BLOCK"
    blocked2 = run_repair_apply("brp-x", confirm="BROWSER_SITE_REPAIR_APPLY")
    assert blocked2["mutated"] is False


def test_run_browser_diff_with_har_imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Avoid live OS/profile by injecting raw via monkeypatch of baseline
    monkeypatch.setattr(
        "windows_network_toolkit.diagnostics.browser_profile.runner.collect_raw_network_baseline",
        lambda *a, **k: _raw_ok(),
    )
    monkeypatch.setattr(
        "windows_network_toolkit.diagnostics.browser_profile.runner.get_adapter",
        lambda browser: _FakeAdapter(),
    )
    result = run_browser_diff(
        "https://www.104.com.tw/",
        browser="edge",
        proof=True,
        normal_har=FIX / "normal_redirect_loop.har.json",
        private_har=FIX / "private_ok.har.json",
    )
    assert result.classification in {
        BrowserDiffClassification.AUTHENTICATION_REDIRECT_LOOP,
        BrowserDiffClassification.SITE_DATA_OR_COOKIE_LOOP,
        BrowserDiffClassification.OS_NETWORK_OK_BROWSER_PROFILE_FAIL,
    }
    assert "SUPERSECRET" not in json.dumps(result.to_dict())
    assert result.raw_network.direct_probe_ok


def test_os_baseline_inject() -> None:
    baseline = collect_raw_network_baseline("https://x.test", inject=_raw_ok().model_dump())
    assert baseline.dns_ok is True


def test_cli_browser_diff_fixture() -> None:
    from windows_network_toolkit import cli

    code = cli.main(
        [
            "browser-diff",
            "https://www.104.com.tw/",
            "--browser",
            "edge",
            "--fixture",
            str(FIX / "104_profile_fail.json"),
            "--format",
            "json",
        ]
    )
    assert code == 0


def test_cli_repair_preview() -> None:
    from windows_network_toolkit import cli

    # May find no profile — still should return 0 with JSON
    code = cli.main(["browser-profile", "repair-preview", "104.com.tw", "--browser", "edge"])
    assert code == 0


class _FakeAdapter:
    name = "edge"

    def detect_installation(self):
        return {"installed": True}

    def discover_profiles(self):
        return []

    def collect_profile_metadata(self, p):
        return p

    def collect_policy_metadata(self):
        return []

    def collect_extension_metadata(self, p):
        return []

    def collect_site_state_metadata(self, domain, p):
        from windows_network_toolkit.diagnostics.browser_profile.models import (
            BrowserSiteStateEvidence,
        )

        return BrowserSiteStateEvidence(domain=domain, cookie_count=2)

    def collect_network_preferences(self, p):
        from windows_network_toolkit.diagnostics.browser_profile.models import (
            BrowserNetworkPreferenceEvidence,
        )

        return BrowserNetworkPreferenceEvidence()

    def run_controlled_probe(self, url, mode):
        return {"available": False, "mode": mode}
