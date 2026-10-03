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
    _load_browser_diff_fixture,
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


def test_fixture_loader_rejects_paths_outside_allowlist(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outside allowlist"):
        _load_browser_diff_fixture(tmp_path / "missing.json")

    external = tmp_path / "fixture.json"
    external.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="outside allowlist"):
        _load_browser_diff_fixture(external)

    with pytest.raises(ValueError, match="outside allowlist"):
        _load_browser_diff_fixture(FIX / "missing.json")


def test_fixture_loader_reads_allowlisted_fixture() -> None:
    data = _load_browser_diff_fixture(FIX / "104_profile_fail.json")
    assert isinstance(data, dict)


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
    assert (
        any("Cookie" in n or "header:Cookie" in n or "header:cookie" in n.lower() for n in notes)
        or notes
    )
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
        raw=_raw_ok(
            dns_ok=False, tcp_ok=False, tls_ok=False, direct_probe_ok=False, http_status=None
        ),
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
    cls, *_ = classify_browser_diff(
        raw=_raw_ok(),
        har=har_fail,
        site_state=None,
        extensions=[],
        network_prefs=None,
        policies=None,
    )
    assert cls == BrowserDiffClassification.NO_DIFF_BOTH_FAIL
    har_ok = compare_hars(ok, ok)
    cls2, *_ = classify_browser_diff(
        raw=_raw_ok(), har=har_ok, site_state=None, extensions=[], network_prefs=None, policies=None
    )
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


def test_repair_apply_requires_confirm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    blocked = run_repair_apply("brp-x", confirm="")
    assert blocked["decision"] == "BLOCK"
    assert blocked["reason"] == "confirm_token_mismatch"
    missing = run_repair_apply("brp-missing", confirm="BROWSER_SITE_REPAIR_APPLY")
    assert missing["decision"] == "BLOCK"
    assert missing["reason"] == "preview_not_found"


def test_repair_apply_clears_domain_cookies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from windows_network_toolkit.diagnostics.browser_profile.runner import (
        save_repair_preview,
    )

    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    profile = tmp_path / "Default"
    network = profile / "Network"
    network.mkdir(parents=True)
    cookies_db = network / "Cookies"
    con = __import__("sqlite3").connect(str(cookies_db))
    con.execute(
        "CREATE TABLE cookies (host_key TEXT, name TEXT, path TEXT, "
        "is_secure INTEGER, is_httponly INTEGER, samesite INTEGER, expires_utc INTEGER)"
    )
    con.execute("INSERT INTO cookies VALUES ('.cambridge.org', 'a', '/', 1, 0, 0, 0)")
    con.execute("INSERT INTO cookies VALUES ('evil.example', 'b', '/', 1, 0, 0, 0)")
    con.commit()
    con.close()

    idb = profile / "IndexedDB" / "https_dictionary.cambridge.org_0.indexeddb.leveldb"
    idb.mkdir(parents=True)
    (idb / "LOG").write_text("x", encoding="utf-8")
    prefs = profile / "Preferences"
    prefs.write_text(
        json.dumps(
            {
                "profile": {
                    "content_settings": {
                        "exceptions": {
                            "cookies": {
                                "https://dictionary.cambridge.org,*": {"setting": 1},
                                "https://other.example,*": {"setting": 1},
                            }
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    preview = build_repair_preview(
        "dictionary.cambridge.org",
        browser="edge",
        has_cookies=True,
        has_service_workers=False,
        has_cache=False,
    )
    dumped = preview.model_dump(mode="json")
    save_repair_preview(dumped)

    result = run_repair_apply(
        preview.preview_id,
        confirm="BROWSER_SITE_REPAIR_APPLY",
        profile_path=profile,
        stop_browser=False,
    )
    assert result["decision"] == "ALLOW"
    assert result["mutated"] is True
    con2 = __import__("sqlite3").connect(str(cookies_db))
    hosts = [r[0] for r in con2.execute("SELECT host_key FROM cookies").fetchall()]
    con2.close()
    assert "evil.example" in hosts
    assert not any("cambridge" in h for h in hosts)
    assert not idb.exists()
    prefs_data = json.loads(prefs.read_text(encoding="utf-8"))
    cookies_exc = prefs_data["profile"]["content_settings"]["exceptions"]["cookies"]
    assert "https://other.example,*" in cookies_exc
    assert "https://dictionary.cambridge.org,*" not in cookies_exc


def test_repair_apply_skips_extension_disable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from windows_network_toolkit.diagnostics.browser_profile.runner import save_repair_preview

    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    profile = tmp_path / "Default"
    profile.mkdir(parents=True)
    preview = build_repair_preview(
        "dictionary.cambridge.org",
        browser="edge",
        proxy_extension_ids=["abcdefghijklmnop"],
    )
    dumped = preview.model_dump(mode="json")
    save_repair_preview(dumped)
    result = run_repair_apply(
        preview.preview_id,
        confirm="BROWSER_SITE_REPAIR_APPLY",
        profile_path=profile,
        stop_browser=False,
    )
    assert result["decision"] == "ALLOW"
    assert any(
        s.get("id", "").startswith("disable_extension_")
        and s.get("reason") == "never_auto_disable_extensions"
        for s in result["skipped"]
    )


def test_safety_token_browser_site_repair() -> None:
    from windows_network_toolkit.safety import CONFIRMATION_TOKENS

    assert CONFIRMATION_TOKENS["BROWSER_SITE_REPAIR_APPLY"] == "BROWSER_SITE_REPAIR_APPLY"


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


def test_allowlist_rejects_symlink_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Symlinks under a fixture root must not expose files outside that root."""
    from windows_network_toolkit.diagnostics.browser_profile import runner as runner_mod

    root = tmp_path / "fixtures"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    external = outside / "external.json"
    external.write_text("{}", encoding="utf-8")
    link = root / "fixture.json"
    try:
        link.symlink_to(external)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")

    monkeypatch.setattr(runner_mod, "_ALLOWED_FIXTURE_ROOTS", (root,))
    monkeypatch.setattr(runner_mod, "_REPO_ROOT", tmp_path)

    with pytest.raises(ValueError, match="outside allowlist"):
        runner_mod._read_json_under_allowlist(link)
    with pytest.raises(ValueError, match="outside allowlist"):
        runner_mod._read_json_under_allowlist(external)
