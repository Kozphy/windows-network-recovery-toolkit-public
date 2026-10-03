"""Tests for public mirror exporter and fixture-mode public API app."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
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
    if not (REPO_ROOT / "config" / "public_mirror").is_dir():
        pytest.skip("rewrite templates are private-only; the full export runs in the private repo")
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


def test_manifest_audit_gate_scans_whole_export_first() -> None:
    mod = _load_export_module()
    checks = mod._load_manifest(MANIFEST)["required_checks"]
    audit = checks[0]
    assert audit["name"] == "public_release_audit"
    assert "--include-untracked" in audit["command"]
    assert "--tracked-only" not in audit["command"]


def test_clean_reexport_preserves_public_git_and_drops_stale_files(tmp_path: Path) -> None:
    mod = _load_export_module()
    repo = tmp_path / "private"
    (repo / "backend").mkdir(parents=True)
    (repo / "backend" / "public_app.py").write_text("app = None\n", encoding="utf-8")
    (repo / "README.md.template").write_text("# Public edition\n", encoding="utf-8")
    manifest = repo / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "include_paths": ["backend/"],
                "exclude_globs": ["**/.env"],
                "rewrite_files": {"README.md": "README.md.template"},
            }
        ),
        encoding="utf-8",
    )

    out = tmp_path / "public_checkout"
    (out / ".git").mkdir(parents=True)
    (out / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (out / "stale_private_only.py").write_text("x = 1\n", encoding="utf-8")
    (out / "old_dir").mkdir()
    (out / "old_dir" / "leftover.txt").write_text("gone\n", encoding="utf-8")

    mod.export_mirror(repo_root=repo, manifest_path=manifest, out_dir=out, clean=True)

    assert (out / ".git" / "HEAD").read_text(encoding="utf-8") == "ref: refs/heads/main\n"
    assert not (out / "stale_private_only.py").exists()
    assert not (out / "old_dir").exists()
    assert (out / "backend" / "public_app.py").is_file()
    assert (out / "README.md").read_text(encoding="utf-8") == "# Public edition\n"


def test_export_skips_untracked_files_in_git_checkout(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    mod = _load_export_module()
    repo = tmp_path / "private"
    (repo / "backend").mkdir(parents=True)
    (repo / "backend" / "public_app.py").write_text("app = None\n", encoding="utf-8")
    (repo / "backend" / "local_draft.py").write_text("SECRET = 1\n", encoding="utf-8")
    (repo / "README.md.template").write_text("# Public edition\n", encoding="utf-8")
    manifest = repo / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "include_paths": ["backend/"],
                "rewrite_files": {"README.md": "README.md.template"},
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "add", "backend/public_app.py", "README.md.template", "manifest.json"],
        cwd=repo,
        check=True,
    )

    out = tmp_path / "export"
    summary = mod.export_mirror(repo_root=repo, manifest_path=manifest, out_dir=out, clean=True)

    assert (out / "backend" / "public_app.py").is_file()
    assert not (out / "backend" / "local_draft.py").exists()
    assert summary["skipped_untracked"] == ["backend/local_draft.py"]


def test_manifest_ruff_check_matches_public_ci() -> None:
    mod = _load_export_module()
    checks = {c["name"]: c["command"] for c in mod._load_manifest(MANIFEST)["required_checks"]}
    workflow = (REPO_ROOT / ".github" / "workflows" / "public-mirror-ci.yml").read_text(
        encoding="utf-8"
    )
    ci_ruff = next(
        line.split("run:", 1)[1].split()
        for line in workflow.splitlines()
        if "run:" in line and "ruff check" in line
    )
    assert checks["ruff"] == ci_ruff


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
