"""Tests for read-only edge-triage routing and token-annotated fix ladder (no live probes)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from windows_network_toolkit import cli, edge_triage
from windows_network_toolkit.edge_extension_policy import (
    installed_extension_ids,
    preview_or_apply_disable,
)
from windows_network_toolkit.edge_runtime import analyze_edge_runtime, blocked_extension_ids
from windows_network_toolkit.edge_triage import last_blank_screen_fix, triage_edge_loading
from windows_network_toolkit.why_broken import synthesize_why_broken

ADGUARD = "bgnkhhnnamicmpeenaelnjfhikgbkllg"
UA_SWITCHER = "djflhoibgkdhkhhcedjiklpkjnoahfmg"
NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)

EDGE_STATE = {
    "running": True,
    "hardware_acceleration": {"hardware_acceleration_mode_enabled": False},
    "cache_targets": [],
    "cache_dirs_present": 4,
    "cache_bytes_total": 1_372_000_000,
}


def _why(primary: dict) -> dict:
    return {"primary_hypothesis": primary, "signals": {}}


CLIENT_PRIMARY = _why(
    {"id": "client_or_site", "classification": "CLIENT_OR_SITE_LIKELY", "score": 0.55}
)


def _write_fix_audit(root: Path, stamp: str) -> None:
    rows = [
        {"timestamp_utc": stamp, "event": "browser_blank_screen_fix", "dry_run": True},
        {
            "timestamp_utc": stamp,
            "event": "browser_blank_screen_fix",
            "dry_run": False,
            "action_allowed": True,
        },
    ]
    (root / "browser-blank-screen.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )


def _triage(tmp_path: Path, **kw) -> dict:
    kw.setdefault("why_broken", CLIENT_PRIMARY)
    kw.setdefault("edge_state", EDGE_STATE)
    kw.setdefault("installed_ids", set())
    kw.setdefault("audit_root", tmp_path)
    kw.setdefault("now", NOW)
    return triage_edge_loading(**kw)


def test_why_broken_mitigated_ipv6_does_not_dominate() -> None:
    result = synthesize_why_broken(
        proxy={"classification": "NO_PROXY"},
        dns={"classification": "DNS_EDGE_OK"},
        ipv6={
            "network_context": {"has_global_ipv6": False},
            "path": {
                "classification": "IPV6_PATH_BLACKHOLE",
                "prefer_ipv4_bit_set": True,
                "wifi_ipv6_binding_enabled": False,
            },
        },
    )
    ipv6 = next(h for h in result["hypotheses"] if h["id"] == "ipv6_path")
    assert ipv6["ipv6_mitigated"] is True
    assert ipv6["score"] < 0.4
    assert result["primary_hypothesis"]["id"] == "client_or_site"
    assert "edge-triage" in result["operator_next_step"]["command"]


def test_why_broken_unmitigated_ipv6_still_primary_when_binding_unknown() -> None:
    result = synthesize_why_broken(
        proxy={"classification": "NO_PROXY"},
        dns={"classification": "DNS_EDGE_OK"},
        ipv6={"path": {"classification": "IPV6_PATH_BLACKHOLE", "prefer_ipv4_bit_set": True}},
    )
    assert result["primary_hypothesis"]["id"] == "ipv6_path"
    assert result["primary_hypothesis"]["ipv6_mitigated"] is False


def test_network_route_recommends_proxy_token(tmp_path: Path) -> None:
    payload = _triage(
        tmp_path,
        why_broken=_why({"id": "proxy", "classification": "DEAD_LOCALHOST_PROXY", "score": 0.95}),
    )
    assert payload["route"] == "network"
    assert payload["recommended_fix"]["token"] == "DISABLE_WININET_PROXY"
    assert "--confirm DISABLE_WININET_PROXY" in payload["recommended_fix"]["apply_command"]
    assert payload["governance"]["execution_authority"] == "preview_only"


def test_ipv6_with_prefer_already_set_is_not_network_route(tmp_path: Path) -> None:
    payload = _triage(
        tmp_path,
        why_broken=_why(
            {
                "id": "ipv6_path",
                "classification": "IPV6_PATH_BLACKHOLE",
                "score": 0.72,
                "prefer_ipv4_bit_set": True,
            }
        ),
    )
    assert payload["route"] == "edge_client"


def test_unknown_inprivate_recommends_cache_and_asks_one_question(tmp_path: Path) -> None:
    payload = _triage(tmp_path, installed_ids={ADGUARD, UA_SWITCHER})
    assert payload["route"] == "edge_client"
    assert payload["recommended_fix"]["token"] == "CLEAR_EDGE_BLANK_SCREEN_CACHES"
    assert "~1372 MB" in payload["recommended_fix"]["changes"]
    ask = payload["ask_user"]
    assert "InPrivate" in ask
    assert "DISABLE_EDGE_EXTENSIONS_VIA_POLICY" in ask
    assert "CLEAR_EDGE_BLANK_SCREEN_CACHES" in ask


def test_inprivate_works_prefers_installed_risky_extensions(tmp_path: Path) -> None:
    payload = _triage(tmp_path, inprivate="works", installed_ids={ADGUARD})
    rec = payload["recommended_fix"]
    assert payload["classification"] == "EDGE_PROFILE_STATE_LIKELY"
    assert rec["token"] == "DISABLE_EDGE_EXTENSIONS_VIA_POLICY"
    assert "AdGuard" in rec["changes"]
    assert "User-Agent" not in rec["changes"]
    assert "RESTORE_EDGE_EXTENSIONS_POLICY" in rec["undo"]


def test_inprivate_works_without_risky_extensions_offers_site_repair(tmp_path: Path) -> None:
    payload = _triage(tmp_path, inprivate="works", url="https://www.example.com/page")
    rec = payload["recommended_fix"]
    assert rec["token"] == "BROWSER_SITE_REPAIR_APPLY"
    assert "repair-preview www.example.com" in rec["preview_command"]
    assert rec["requires_input"] is None


def test_site_rung_requests_url_when_missing(tmp_path: Path) -> None:
    payload = _triage(tmp_path, inprivate="works")
    assert payload["recommended_fix"]["requires_input"] == "url"
    assert "site address" in payload["ask_user"]


def test_recent_live_fix_escalates_instead_of_repeating_cache_clear(tmp_path: Path) -> None:
    _write_fix_audit(tmp_path, "2026-10-02T06:43:00Z")
    payload = _triage(tmp_path, inprivate="fails")
    assert payload["classification"] == "EDGE_STATE_EXHAUSTED_ESCALATE"
    assert payload["recommended_fix"] is None
    assert payload["operator_next_step"]["kind"] == "escalate"
    assert payload["fix_options"][0]["recently_applied"] is True


def test_recent_fix_with_unknown_inprivate_moves_cache_down(tmp_path: Path) -> None:
    _write_fix_audit(tmp_path, "2026-10-02T06:43:00Z")
    payload = _triage(tmp_path, installed_ids={ADGUARD})
    assert payload["recommended_fix"]["id"] == "block_risky_extensions"
    assert payload["fix_options"][-1]["id"] == "clear_edge_caches"
    assert "CLEAR_EDGE_BLANK_SCREEN_CACHES" not in payload["ask_user"]
    assert "another browser" in payload["ask_user"]


def test_old_fix_outside_window_is_not_recent(tmp_path: Path) -> None:
    _write_fix_audit(tmp_path, "2026-09-20T00:00:00Z")
    fix = last_blank_screen_fix(tmp_path, now=NOW)
    assert fix is not None and fix["recent"] is False
    assert _triage(tmp_path, inprivate="fails")["recommended_fix"]["id"] == "clear_edge_caches"


def test_dry_run_only_audit_rows_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "browser-blank-screen.jsonl").write_text(
        json.dumps({"event": "browser_blank_screen_fix", "dry_run": True}) + "\nnot json\n",
        encoding="utf-8",
    )
    assert last_blank_screen_fix(tmp_path, now=NOW) is None


def test_url_both_fail_routes_unreachable(tmp_path: Path) -> None:
    payload = _triage(
        tmp_path,
        why_broken=_why({"id": "url_probe", "classification": "URL_BOTH_FAIL", "score": 0.75}),
    )
    assert payload["route"] == "unreachable"
    assert payload["fix_options"] == []


def test_invalid_inprivate_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _triage(tmp_path, inprivate="maybe")


def test_triage_never_mutates(tmp_path: Path) -> None:
    cache = tmp_path / "Default" / "GPUCache"
    cache.mkdir(parents=True)
    (cache / "data_0").write_bytes(b"x")
    triage_edge_loading(
        why_broken=CLIENT_PRIMARY,
        inprivate="fails",
        audit_root=tmp_path,
        user_data_dir=tmp_path,
        now=NOW,
        runtime_sample={"processes": []},
        blocked_ids=set(),
    )
    assert (cache / "data_0").exists()


def test_installed_extension_ids_and_preview_annotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WNT_AUDIT_DIR", str(tmp_path / "audit"))
    assert installed_extension_ids(tmp_path) is None
    ext = tmp_path / "Default" / "Extensions"
    (ext / ADGUARD).mkdir(parents=True)
    (ext / "Temp").mkdir()
    assert installed_extension_ids(tmp_path) == {ADGUARD}

    payload = preview_or_apply_disable(
        preset="cloudflare-risk", dry_run=True, user_data_dir=tmp_path
    )
    flags = {t["id"]: t["installed"] for t in payload["targets"]}
    assert flags == {ADGUARD: True, UA_SWITCHER: False}
    assert payload["action_allowed"] is False


def test_cli_edge_triage_passes_operator_evidence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict = {}

    def fake(**kw):
        seen.update(kw)
        return {"route": "edge_client"}

    monkeypatch.setattr(edge_triage, "triage_edge_loading", fake)
    rc = cli.main(["edge-triage", "--inprivate", "works", "--url", "https://x.test/"])
    assert rc == 0
    assert seen == {"url": "https://x.test/", "inprivate": "works", "sample_seconds": 3.0}
    assert json.loads(capsys.readouterr().out)["route"] == "edge_client"


def _proc(pid: int, ptype: str, cpu: float = 0.0, **extra) -> dict:
    row = {"pid": pid, "type": ptype, "cpu_seconds": cpu, "mb": 200}
    row.setdefault("start_utc", "2026-10-02T06:44:00Z")
    row.update(extra)
    return row


def _sample(*procs: dict, free_mb: int = 12_000, total_mb: int = 32_000, gpus=None) -> dict:
    return {
        "processes": list(procs),
        "free_mb": free_mb,
        "total_mb": total_mb,
        "gpus": gpus or ["Intel(R) UHD Graphics"],
    }


def test_frozen_tab_is_detected_and_leads_ask_user(tmp_path: Path) -> None:
    sample = _sample(
        _proc(1, "browser"),
        _proc(2, "renderer", cpu=3.3),
        _proc(3, "renderer", cpu=0.1),
        _proc(4, "renderer", cpu=3.0, extension=True),
    )
    payload = _triage(tmp_path, runtime_sample=sample)
    ids = [i["id"] for i in payload["detected_issues"]]
    assert ids == ["tab_frozen", "extension_busy"]
    tab = payload["detected_issues"][0]
    assert tab["evidence"] == [
        {"pid": 2, "extension": False, "cpu_percent_of_core": 110, "mb": 200}
    ]
    assert payload["diagnosis"] == tab["summary"]
    assert payload["ask_user"].startswith("First: Click 'Exit page'")
    assert payload["manual_steps"][0] == tab["user_action"]
    assert payload["runtime"]["edge_process_count"] == 4


def test_restart_pending_after_live_policy_change(tmp_path: Path) -> None:
    (tmp_path / "edge-extensions-policy.jsonl").write_text(
        json.dumps(
            {
                "event": "edge_extensions_disable",
                "dry_run": False,
                "mutated": True,
                "timestamp_utc": "2026-10-02T08:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    payload = _triage(tmp_path, runtime_sample=_sample(_proc(1, "browser")))
    assert [i["id"] for i in payload["detected_issues"]] == ["restart_pending"]
    assert payload["ask_user"].startswith("First: Close Edge completely")


def test_edge_started_after_fix_is_not_restart_pending(tmp_path: Path) -> None:
    _write_fix_audit(tmp_path, "2026-10-02T06:00:00Z")
    payload = _triage(tmp_path, runtime_sample=_sample(_proc(1, "browser")))
    assert payload["detected_issues"] == []
    assert payload["diagnosis"].startswith("Network path looks fine")


def test_memory_pressure_detected(tmp_path: Path) -> None:
    payload = _triage(
        tmp_path, runtime_sample=_sample(_proc(1, "browser"), free_mb=900, total_mb=16_000)
    )
    assert [i["id"] for i in payload["detected_issues"]] == ["memory_pressure"]
    assert not payload["ask_user"].startswith("First:")


def test_gpu_off_flag_reported_only_with_capable_gpu(tmp_path: Path) -> None:
    flagged = _proc(5, "gpu-process", gpu_disabled_flag=True)
    weak = _triage(tmp_path, runtime_sample=_sample(_proc(1, "browser"), flagged))
    assert weak["detected_issues"] == []
    strong = _triage(
        tmp_path,
        runtime_sample=_sample(_proc(1, "browser"), flagged, gpus=["NVIDIA GeForce RTX 4060"]),
    )
    assert [i["id"] for i in strong["detected_issues"]] == ["gpu_acceleration_off"]


def test_policy_blocked_extensions_drop_extension_rung(tmp_path: Path) -> None:
    payload = _triage(
        tmp_path,
        inprivate="works",
        installed_ids={ADGUARD, UA_SWITCHER},
        blocked_ids={ADGUARD, UA_SWITCHER},
        url="https://www.facebook.com/big4page/",
    )
    assert all(r["blocked_by_policy"] for r in payload["risky_extensions"])
    assert "block_risky_extensions" not in [o["id"] for o in payload["fix_options"]]
    assert payload["recommended_fix"]["token"] == "BROWSER_SITE_REPAIR_APPLY"


def _write_site_repair_audit(root: Path, domain: str, *, mutated: bool = True) -> None:
    row = {
        "event": "browser_repair_apply",
        "decision": "ALLOW",
        "mutated": mutated,
        "domain": domain,
        "preview_id": "brp-test",
        "timestamp_utc": "2026-10-02T04:43:45Z",
    }
    (root / "browser-diff.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")


def test_only_untried_rung_is_offered_as_bare_token(tmp_path: Path) -> None:
    _write_fix_audit(tmp_path, "2026-10-02T06:43:00Z")
    sample = _sample(_proc(1, "browser"), _proc(2, "renderer", cpu=3.3))
    payload = _triage(
        tmp_path,
        url="https://www.facebook.com/big4page/",
        installed_ids={ADGUARD, UA_SWITCHER},
        blocked_ids={ADGUARD, UA_SWITCHER},
        runtime_sample=sample,
    )
    assert payload["recommended_fix"]["token"] == "BROWSER_SITE_REPAIR_APPLY"
    assert payload["ask_kind"] == "token"
    ask = payload["ask_user"]
    assert ask.startswith("Reply BROWSER_SITE_REPAIR_APPLY to apply: Closes Edge")
    assert "InPrivate" not in ask
    assert "Closing Edge also clears the detected issue" in ask


def test_previous_site_repair_is_recommended_first(tmp_path: Path) -> None:
    _write_site_repair_audit(tmp_path, "facebook.com")
    payload = _triage(tmp_path, url="https://www.facebook.com/", installed_ids={ADGUARD})
    assert payload["classification"] == "SITE_DATA_FIXED_BEFORE"
    assert payload["previous_site_repair"]["domain"] == "facebook.com"
    rec = payload["recommended_fix"]
    assert rec["id"] == "repair_site_data"
    assert rec["previously_applied"]["timestamp_utc"] == "2026-10-02T04:43:45Z"
    assert payload["ask_kind"] == "token"
    assert payload["ask_user"].startswith("Reply BROWSER_SITE_REPAIR_APPLY")


def test_previous_site_repair_ignored_for_other_domains_and_inprivate_fails(
    tmp_path: Path,
) -> None:
    _write_site_repair_audit(tmp_path, "facebook.com")
    other = _triage(tmp_path, url="https://notfacebook.com/")
    assert other["previous_site_repair"] is None
    assert other["recommended_fix"]["id"] == "clear_edge_caches"
    fails = _triage(tmp_path, url="https://www.facebook.com/", inprivate="fails")
    assert fails["classification"] == "EDGE_CACHE_GPU_LIKELY"


def test_unmutated_site_repair_rows_are_ignored(tmp_path: Path) -> None:
    _write_site_repair_audit(tmp_path, "facebook.com", mutated=False)
    assert edge_triage.last_site_repair(tmp_path, "www.facebook.com") is None


def test_blocked_extension_ids_parses_policy_json() -> None:
    raw = json.dumps(
        {ADGUARD: {"installation_mode": "blocked"}, UA_SWITCHER: {"installation_mode": "allowed"}}
    )
    assert blocked_extension_ids(raw) == {ADGUARD}
    assert blocked_extension_ids(None) == set()
    assert blocked_extension_ids("not json") == set()


def test_unsampled_runtime_reports_no_issues() -> None:
    result = analyze_edge_runtime(None)
    assert result == {"sampled": False, "issues": [], "limitations": result["limitations"]}
    assert result["limitations"]
