"""JSON CLI contract tests."""

from __future__ import annotations

import json
from unittest.mock import patch

from windows_network_toolkit import cli


def test_proxy_status_fixture_json(capsys) -> None:
    rc = cli.main(["proxy-status", "--fixture", "dead_proxy_59081.json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["classification"] == "DEAD_PROXY_CONFIG"
    assert "classification_result" in payload


def test_proxy_owner_fixture_json(capsys) -> None:
    rc = cli.main(["proxy-owner", "--fixture", "dead_proxy_59081.json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["listener_found"] is False


def test_diagnose_proof_fixture_json(capsys) -> None:
    rc = cli.main(["diagnose", "--proof", "--fixture", "dead_proxy_59081.json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["conclusion"]["status"] == "supported"


def test_proxy_disable_dry_run_json(capsys) -> None:
    with patch("windows_network_toolkit.proxy_remediation.platform.system", return_value="Linux"):
        cli.main(["proxy-disable"])
    payload = json.loads(capsys.readouterr().out)
    assert payload.get("unsupported_platform") or payload.get("dry_run") is True
