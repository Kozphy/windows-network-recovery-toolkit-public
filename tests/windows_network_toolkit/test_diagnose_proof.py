"""Diagnose proof envelope tests."""

from __future__ import annotations

import json
from pathlib import Path

from windows_network_toolkit.proof import run_diagnose_proof

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "enert" / "dead_proxy_59081.json"


def test_dead_proxy_proof_supported() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    result = run_diagnose_proof(inject=data["proof"])
    assert result.conclusion_status == "supported"
    assert result.confidence >= 0.9
    assert any("malware" in x.lower() for x in result.limitations)
    assert any("mitm" in x.lower() for x in result.limitations)


def test_proof_attempts_present() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    result = run_diagnose_proof(inject=data["proof"])
    names = {a.name for a in result.proof_attempts}
    assert "localhost_listener_check" in names
