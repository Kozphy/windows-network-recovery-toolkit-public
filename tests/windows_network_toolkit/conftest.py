"""Shared fixtures for windows_network_toolkit tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_audit_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Route audit appends to a temp dir.

    edge-triage reads the real ``.audit`` logs to decide whether a fix was applied
    recently, so test rows written there would steer live triage on the operator's PC.
    """
    root = tmp_path / "audit"
    monkeypatch.setenv("WNT_AUDIT_DIR", str(root))
    return root
