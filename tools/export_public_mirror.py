#!/usr/bin/env python3
"""Export a sanitized public-mirror tree from the private monorepo.

Module responsibility:
    Copy allowlisted paths from ``config/public_mirror_manifest.yaml``, apply
    exclude globs, rewrite public README/pyproject/AGENTS, and optionally run
    audit + focused pytest checks. Inside a git checkout only git-tracked files
    are copied, so untracked local drafts never reach the public mirror.

System placement:
    Private-repo operator tool. Does not push to GitHub by itself — prints
    bootstrap commands for the public remote.

Side effects:
    Writes files under ``--out`` (default ``.public_mirror_export/``).
    May run subprocess checks when ``--run-checks`` is set.

Failure modes:
    Missing manifest/templates → exit 2. High-risk audit findings → exit 1.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "config" / "public_mirror_manifest.yaml"
DEFAULT_OUT = REPO_ROOT / ".public_mirror_export"

# Keep example env files even if a parent pattern would drop ``.env*``.
_KEEP_BASENAMES = frozenset(
    {
        ".env.example",
        ".env.local.example",
    }
)


def _load_manifest(path: Path) -> dict[str, Any]:
    """Load YAML or JSON manifest.

    Args:
        path: Manifest file path.

    Returns:
        Parsed mapping.

    Raises:
        FileNotFoundError: When path is missing.
        ValueError: When content cannot be parsed.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Manifest not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover
            raise ValueError(
                "PyYAML is required to load .yaml manifests. Install with: pip install PyYAML"
            ) from exc
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Manifest root must be a mapping")
    return data


def _posix_rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _is_excluded(rel_posix: str, patterns: list[str]) -> bool:
    name = Path(rel_posix).name
    if name in _KEEP_BASENAMES:
        return False
    for pattern in patterns:
        if fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(name, pattern):
            return True
        # Also match directory prefixes like logs/**
        if pattern.endswith("/**") and rel_posix.startswith(pattern[:-3]):
            return True
    return False


def _copy_path(src: Path, dest: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
    elif src.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def _git_ls_files(repo_root: Path, *extra: str) -> set[str]:
    """Run ``git ls-files -z`` and return posix repo-relative paths.

    Raises:
        RuntimeError: When git is unavailable or the command fails — exporting
            without the tracked list could publish local files.
    """
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", *extra],
            cwd=str(repo_root),
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"git ls-files failed in {repo_root}: {exc}") from exc
    return {p for p in completed.stdout.decode("utf-8").split("\0") if p}


def _under(path: str, rel: str) -> bool:
    root = rel.rstrip("/")
    return path == root or path.startswith(root + "/")


def _clean_export_dir(out_dir: Path) -> None:
    """Empty ``out_dir`` while keeping a public-repo ``.git`` checkout intact.

    Args:
        out_dir: Export directory, possibly a clone of the public mirror repo.

    Side effects:
        Deletes every top-level entry except ``.git`` so files removed from the
        private allowlist also disappear from the next public commit.
    """
    for child in out_dir.iterdir():
        if child.name == ".git":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _remove_excluded(export_root: Path, patterns: list[str]) -> list[str]:
    removed: list[str] = []
    # Walk files deepest-first so directories can be cleaned afterward.
    all_paths = sorted(export_root.rglob("*"), key=lambda p: len(p.parts), reverse=True)
    for path in all_paths:
        if path == export_root:
            continue
        rel = _posix_rel(path, export_root)
        if rel == ".git" or rel.startswith(".git/"):
            continue
        if _is_excluded(rel, patterns):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                path.unlink(missing_ok=True)
            removed.append(rel)
    return removed


def _apply_rewrites(export_root: Path, rewrites: dict[str, str], repo_root: Path) -> None:
    for dest_rel, template_rel in rewrites.items():
        template = repo_root / template_rel
        if not template.is_file():
            raise FileNotFoundError(f"Rewrite template missing: {template}")
        target = export_root / dest_rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")


def _write_mirror_meta(export_root: Path, manifest: dict[str, Any]) -> None:
    meta = {
        "edition": "public",
        "manifest_version": manifest.get("version"),
        "public_repo_name": manifest.get("public_repo_name"),
        "source": "private-monorepo-export",
        "api_entrypoint": "backend.public_app:app",
    }
    (export_root / ".public_mirror.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )


def export_mirror(
    *,
    repo_root: Path,
    manifest_path: Path,
    out_dir: Path,
    clean: bool = True,
) -> dict[str, Any]:
    """Build the public mirror export directory.

    Args:
        repo_root: Private monorepo root.
        manifest_path: Path to public_mirror_manifest.yaml.
        out_dir: Destination directory.
        clean: When true, empty out_dir before copy, preserving any ``.git``
            so a public-repo checkout can be re-exported in place.

    Returns:
        Summary dict with copied/removed/rewritten counts.
    """
    manifest = _load_manifest(manifest_path)
    include_paths = list(manifest.get("include_paths") or [])
    exclude_globs = list(manifest.get("exclude_globs") or [])
    rewrites = dict(manifest.get("rewrite_files") or {})

    out_dir.mkdir(parents=True, exist_ok=True)
    if clean:
        _clean_export_dir(out_dir)

    in_git = (repo_root / ".git").exists()
    tracked = _git_ls_files(repo_root) if in_git else set()
    untracked = _git_ls_files(repo_root, "--others", "--exclude-standard") if in_git else set()
    copied: list[str] = []
    missing: list[str] = []
    skipped_untracked: list[str] = []
    for rel in include_paths:
        src = repo_root / rel
        if not src.exists():
            missing.append(rel)
            continue
        if in_git:
            for path in sorted(p for p in tracked if _under(p, rel)):
                if (repo_root / path).is_file():
                    _copy_path(repo_root / path, out_dir / path)
            skipped_untracked.extend(sorted(p for p in untracked if _under(p, rel)))
        else:
            _copy_path(src, out_dir / rel)
        copied.append(rel.rstrip("/"))

    removed = _remove_excluded(out_dir, exclude_globs)
    _apply_rewrites(out_dir, rewrites, repo_root)
    _write_mirror_meta(out_dir, manifest)

    # Ensure public_app exists in export (copied with backend/).
    if not (out_dir / "backend" / "public_app.py").is_file():
        raise FileNotFoundError("backend/public_app.py missing from export")

    return {
        "out_dir": str(out_dir),
        "copied": copied,
        "missing_includes": missing,
        "skipped_untracked": skipped_untracked,
        "removed_count": len(removed),
        "rewrites": list(rewrites.keys()),
        "public_repo_name": manifest.get("public_repo_name"),
        "public_default_branch": manifest.get("public_default_branch", "main"),
    }


def run_checks(export_root: Path, manifest: dict[str, Any]) -> int:
    """Run required_checks from the manifest inside the export tree.

    Returns:
        0 if all checks pass; otherwise the first non-zero exit code.
    """
    checks = list(manifest.get("required_checks") or [])
    for check in checks:
        name = check.get("name", "check")
        command = list(check.get("command") or [])
        if not command:
            continue
        print(f"\n==> {name}: {' '.join(command)}")
        completed = subprocess.run(command, cwd=str(export_root), check=False)
        if completed.returncode != 0:
            print(f"Check failed: {name} (exit {completed.returncode})", file=sys.stderr)
            return int(completed.returncode)
    return 0


def print_bootstrap(summary: dict[str, Any]) -> None:
    """Print one-time public repo create + first push commands."""
    out = summary["out_dir"]
    repo = summary.get("public_repo_name") or "windows-network-recovery-toolkit-public"
    branch = summary.get("public_default_branch") or "main"
    print(
        f"""
Bootstrap (one-time) - create public GitHub repo then push export
================================================================
# 1) Create empty PUBLIC repo under Kozphy (web UI or gh):
gh repo create Kozphy/{repo} --public --description "Public mirror: WNRT CLI + fixture demo API"

# 2) From the export directory:
cd "{out}"
git init -b {branch}
git add .
git commit -m "Initial public mirror export from private monorepo."
git remote add origin git@github.com:Kozphy/{repo}.git
git push -u origin {branch}

# Subsequent syncs (from private monorepo root; .git in the export is preserved):
python tools/export_public_mirror.py --out "{out}" --run-checks
cd "{out}"
git add -A
git commit -m "Sync public mirror from private monorepo."
git push

Never force-push secrets. Prefer cherry-picking public fixes back into private.
"""
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry for public mirror export."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Path to public_mirror_manifest.yaml",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Export directory (default: .public_mirror_export/)",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not delete the export directory before copying",
    )
    parser.add_argument(
        "--run-checks",
        action="store_true",
        help="Run manifest required_checks inside the export tree",
    )
    parser.add_argument(
        "--print-bootstrap",
        action="store_true",
        help="Print one-time public repo create/push commands",
    )
    args = parser.parse_args(argv)

    try:
        summary = export_mirror(
            repo_root=REPO_ROOT,
            manifest_path=args.manifest.resolve(),
            out_dir=args.out.resolve(),
            clean=not args.no_clean,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Export failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({k: v for k, v in summary.items() if k != "copied"}, indent=2))
    print(f"Copied {len(summary['copied'])} include roots -> {summary['out_dir']}")
    if summary["missing_includes"]:
        print("WARNING missing includes:", ", ".join(summary["missing_includes"]))

    if args.print_bootstrap or not args.run_checks:
        print_bootstrap(summary)

    if args.run_checks:
        manifest = _load_manifest(args.manifest.resolve())
        code = run_checks(Path(summary["out_dir"]), manifest)
        if code != 0:
            return code

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
