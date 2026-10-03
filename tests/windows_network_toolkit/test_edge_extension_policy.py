"""Tests for gated Edge extension policy CLI helpers."""

from __future__ import annotations

import json

from windows_network_toolkit.edge_extension_policy import (
    DISABLE_TOKEN,
    RESTORE_TOKEN,
    build_extension_settings_json,
    normalize_extension_ids,
    preview_or_apply_disable,
    preview_or_apply_restore,
    resolve_targets,
)
from windows_network_toolkit.safety import CONFIRMATION_TOKENS


def test_tokens_registered() -> None:
    assert CONFIRMATION_TOKENS["DISABLE_EDGE_EXTENSIONS_VIA_POLICY"] == DISABLE_TOKEN
    assert CONFIRMATION_TOKENS["RESTORE_EDGE_EXTENSIONS_POLICY"] == RESTORE_TOKEN


def test_normalize_extension_ids() -> None:
    valid, invalid = normalize_extension_ids(
        ["bgnkhhnnamicmpeenaelnjfhikgbkllg", "NOT-AN-ID", "djflhoibgkdhkhhcedjiklpkjnoahfmg"]
    )
    assert valid == [
        "bgnkhhnnamicmpeenaelnjfhikgbkllg",
        "djflhoibgkdhkhhcedjiklpkjnoahfmg",
    ]
    assert invalid == ["NOT-AN-ID"]


def test_cloudflare_risk_preset() -> None:
    resolved = resolve_targets(preset="cloudflare-risk")
    assert not resolved["errors"]
    ids = [t["id"] for t in resolved["targets"]]
    assert "bgnkhhnnamicmpeenaelnjfhikgbkllg" in ids
    assert "djflhoibgkdhkhhcedjiklpkjnoahfmg" in ids
    blob = build_extension_settings_json(resolved["targets"])
    data = json.loads(blob)
    assert data["bgnkhhnnamicmpeenaelnjfhikgbkllg"]["installation_mode"] == "blocked"


def test_disable_dry_run_default() -> None:
    payload = preview_or_apply_disable(preset="cloudflare-risk", dry_run=True)
    assert payload["dry_run"] is True
    assert payload["action_allowed"] is False
    assert payload["confirmation_required"] == DISABLE_TOKEN
    assert "DISABLE_EDGE_EXTENSIONS_VIA_POLICY" in (
        payload["operator_next_step"].get("command") or ""
    )


def test_disable_blocks_without_token() -> None:
    payload = preview_or_apply_disable(
        preset="cloudflare-risk",
        dry_run=False,
        confirm="WRONG",
    )
    assert payload["action_allowed"] is False
    assert payload.get("mutated") is not True


def test_restore_dry_run() -> None:
    payload = preview_or_apply_restore(dry_run=True)
    assert payload["dry_run"] is True
    assert payload["confirmation_required"] == RESTORE_TOKEN


def test_cli_edge_extensions_disable_preview() -> None:
    from windows_network_toolkit import cli

    code = cli.main(
        [
            "edge-extensions-disable",
            "--preset",
            "cloudflare-risk",
            "--dry-run",
            "true",
        ]
    )
    assert code == 0
