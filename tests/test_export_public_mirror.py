"""Tests for public mirror exporter and fixture-mode public API app."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "config" / "public_mirror_manifest.yaml"


def _load_export_module():
    script = REPO_ROOT / "tools" / "export_public_mirror.py"
    spec = importlib.util.spec_from_file_location("export_public_mirror", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["export_public_mirror"] = module
    spec.loader.exec_module(module)
    return module


def test_exclude_keeps_env_examples() -> None:
    mod = _load_export_module()
    assert mod._is_excluded("frontend/.env.local.example", ["**/.env", "**/.env.local"]) is False
    assert mod._is_excluded("frontend/.env.local", ["**/.env.local"]) is True
    assert mod._is_excluded("backend/billing.py", ["backend/billing.py"]) is True


def test_export_mirror_rewrites_and_includes_public_app(tmp_path: Path) -> None:
    mod = _load_export_module()
    out = tmp_path / "export"
    summary = mod.export_mirror(
        repo_root=REPO_ROOT,
        manifest_path=MANIFEST,
        out_dir=out,
        clean=True,
    )
    assert (out / "backend" / "public_app.py").is_file()
    assert (out / "windows_network_toolkit" / "dns_edge.py").is_file()
    assert (out / "README.md").is_file()
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "Public edition" in readme or "public mirror" in readme.lower()
    pyproject = (out / "pyproject.toml").read_text(encoding="utf-8").lower()
    assert "stripe" not in pyproject
    assert not (out / "backend" / "billing.py").exists()
    meta = json.loads((out / ".public_mirror.json").read_text(encoding="utf-8"))
    assert meta["edition"] == "public"
    assert meta["api_entrypoint"] == "backend.public_app:app"
    assert "windows_network_toolkit" in summary["copied"]


def test_public_app_health() -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from backend.public_app import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("status") == "ok"
    assert payload.get("edition") == "public"
