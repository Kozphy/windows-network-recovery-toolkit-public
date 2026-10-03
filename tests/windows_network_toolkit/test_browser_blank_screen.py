"""Tests for Edge blank-screen diagnose and gated remediation."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from windows_network_toolkit.browser_blank_screen import (
    CONFIRMATION_PHRASE,
    _read_hw_accel,
    classify_blank_screen,
    diagnose_browser_blank_screen,
    remediate_browser_blank_screen,
)
from windows_network_toolkit.safety import CONFIRMATION_TOKENS
from windows_network_toolkit.why_broken import synthesize_why_broken

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "browser_blank_screen"
    / "linkedin_blank_cache_gpu.json"
)


def test_confirmation_token_registered() -> None:
    assert CONFIRMATION_TOKENS["CLEAR_EDGE_BLANK_SCREEN_CACHES"] == CONFIRMATION_PHRASE


def test_classify_cache_gpu_when_origin_ok() -> None:
    row = classify_blank_screen(
        origin_ok=True,
        ipv6_classification="IPV6_PATH_BLACKHOLE",
        prefer_ipv4=True,
        hw_accel_enabled=True,
        cache_dirs_present=2,
    )
    assert row["primary_classification"] == "BROWSER_BLANK_SCREEN_CACHE_GPU"
    assert "browser-blank-screen --with-fix-preview" in row["recommended_next_actions"][0]


def test_classify_ipv6_first_when_prefer_missing() -> None:
    row = classify_blank_screen(
        origin_ok=True,
        ipv6_classification="IPV6_PATH_BLACKHOLE",
        prefer_ipv4=False,
        hw_accel_enabled=True,
        cache_dirs_present=1,
    )
    assert row["primary_classification"] == "IPV6_BLACKHOLE_LIKELY"


def test_classify_unknown_hw_accel_is_not_gpu_evidence() -> None:
    """None prefs must not force CACHE_GPU when no cache dirs exist."""
    mitigated = classify_blank_screen(
        origin_ok=True,
        ipv6_classification="IPV6_PATH_BLACKHOLE",
        prefer_ipv4=True,
        hw_accel_enabled=None,
        cache_dirs_present=0,
    )
    assert mitigated["primary_classification"] == "IPV6_MITIGATED_TRY_BLANK_SCREEN_FIX"

    inconclusive = classify_blank_screen(
        origin_ok=True,
        ipv6_classification="IPV6_PATH_OK",
        prefer_ipv4=True,
        hw_accel_enabled=None,
        cache_dirs_present=0,
    )
    assert inconclusive["primary_classification"] == "INCONCLUSIVE_CLIENT_OR_SITE"


def test_classify_cache_gpu_when_caches_present_even_if_hw_unknown() -> None:
    row = classify_blank_screen(
        origin_ok=True,
        ipv6_classification="IPV6_PATH_OK",
        prefer_ipv4=True,
        hw_accel_enabled=None,
        cache_dirs_present=2,
    )
    assert row["primary_classification"] == "BROWSER_BLANK_SCREEN_CACHE_GPU"


def test_diagnose_fixture_inject() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload = diagnose_browser_blank_screen(inject=data)
    assert payload["classification"] == "BROWSER_BLANK_SCREEN_CACHE_GPU"
    assert "browser-blank-screen" in (payload["operator_next_step"].get("command") or "")


def test_diagnose_with_fix_preview_attaches_dry_run() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="wnt_bbs_prev_") as tmp:
        payload = diagnose_browser_blank_screen(
            inject=data,
            with_fix_preview=True,
            user_data_dir=Path(tmp),
        )
    assert "fix_preview" in payload
    assert payload["fix_preview"]["dry_run"] is True
    assert payload["fix_preview"]["action_allowed"] is False
    assert payload["operator_next_step"]["confirmation_required"] == CONFIRMATION_PHRASE
    assert "CLEAR_EDGE_BLANK_SCREEN_CACHES" in (payload["operator_next_step"].get("command") or "")


def test_remediate_dry_run_default() -> None:
    with tempfile.TemporaryDirectory(prefix="wnt_bbs_") as tmp:
        payload = remediate_browser_blank_screen(dry_run=True, user_data_dir=Path(tmp))
    assert payload["dry_run"] is True
    assert payload["action_allowed"] is False
    assert payload["confirmation_required"] == CONFIRMATION_PHRASE
    assert "CLEAR_EDGE_BLANK_SCREEN_CACHES" in (payload["operator_next_step"].get("command") or "")


def test_remediate_blocks_without_token() -> None:
    with tempfile.TemporaryDirectory(prefix="wnt_bbs_") as tmp:
        payload = remediate_browser_blank_screen(
            dry_run=False,
            confirm="WRONG",
            user_data_dir=Path(tmp),
            stop_edge=False,
        )
    assert payload["action_allowed"] is False
    assert payload["applied_actions"] == []


def test_remediate_apply_clears_cache_and_prefs() -> None:
    with tempfile.TemporaryDirectory(prefix="wnt_bbs_") as tmp:
        root = Path(tmp)
        default = root / "Default"
        gpu = default / "GPUCache"
        gpu.mkdir(parents=True)
        (gpu / "data_0").write_bytes(b"x" * 32)
        prefs = default / "Preferences"
        prefs.write_text(
            json.dumps({"hardware_acceleration_mode_enabled": True}),
            encoding="utf-8",
        )
        payload = remediate_browser_blank_screen(
            dry_run=False,
            confirm=CONFIRMATION_PHRASE,
            user_data_dir=root,
            stop_edge=False,
        )
        assert payload["action_allowed"] is True
        assert not gpu.exists()
        data = json.loads(prefs.read_text(encoding="utf-8"))
        assert data["hardware_acceleration_mode_enabled"] is False


def test_hw_accel_reads_local_state_not_legacy_preferences(tmp_path: Path) -> None:
    prefs = tmp_path / "Preferences"
    prefs.write_text(json.dumps({"hardware_acceleration_mode_enabled": False}), encoding="utf-8")
    local = tmp_path / "Local State"

    local.write_text(json.dumps({"hardware_acceleration_mode": {"enabled": False}}), "utf-8")
    off = _read_hw_accel(prefs, local)
    assert (off["hardware_acceleration_mode_enabled"], off["source"]) == (False, "local_state")

    local.write_text(json.dumps({"browser": {}}), encoding="utf-8")
    default = _read_hw_accel(prefs, local)
    assert default["hardware_acceleration_mode_enabled"] is True
    assert default["source"] == "chromium_default"
    assert default["preferences_legacy_value"] is False


def test_hw_accel_falls_back_to_preferences_without_local_state(tmp_path: Path) -> None:
    prefs = tmp_path / "Preferences"
    prefs.write_text(json.dumps({"hardware_acceleration_mode_enabled": False}), encoding="utf-8")
    legacy = _read_hw_accel(prefs, tmp_path / "missing")
    assert legacy["hardware_acceleration_mode_enabled"] is False
    assert legacy["source"] == "preferences_legacy"


def test_why_broken_points_to_blank_screen_when_prefer_set() -> None:
    result = synthesize_why_broken(
        proxy={"classification": "NO_PROXY"},
        dns={"classification": "DNS_EDGE_OK"},
        ipv6={
            "path": {
                "classification": "IPV6_PATH_BLACKHOLE",
                "prefer_ipv4_bit_set": True,
                "classification_result": {"reasoning": "blackhole"},
            }
        },
        url_probe={
            "url": "https://www.linkedin.com/",
            "host": "www.linkedin.com",
            "ipv4": {"ok": True},
            "ipv6": {"ok": False},
        },
    )
    assert result["primary_hypothesis"]["id"] == "ipv6_path"
    assert "browser-blank-screen" in (result["primary_hypothesis"].get("next_command") or "")
