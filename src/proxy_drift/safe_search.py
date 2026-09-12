"""Timeout-safe targeted file search (no full user-profile recursion)."""

from __future__ import annotations

import fnmatch
import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_DEFAULT_MAX_SECONDS = 20.0
_DEFAULT_MAX_FILES = 3000

_ALWAYS_EXCLUDE_DIR_NAMES = frozenset(
    {
        "node_modules",
        ".git",
        ".cache",
        "docker",
    }
)
_PROFILE_EXCLUDE_DIR_NAMES = frozenset(
    {
        "temp",
        "packages",
        "edge",
        "chrome",
    }
)
_EXCLUDE_DIR_FRAGMENTS = (
    os.path.join("AppData", "Local", "Temp"),
    os.path.join("AppData", "Local", "Packages"),
    os.path.join("AppData", "Local", "Microsoft", "Edge"),
    os.path.join("AppData", "Local", "Google", "Chrome"),
    os.path.join("OneDrive", "."),
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _should_exclude_dir(path: Path, *, profile_scan: bool = False, is_scan_root: bool = False) -> bool:
    parts = {segment.lower() for segment in str(path).replace("\\", "/").split("/")}
    if parts & _ALWAYS_EXCLUDE_DIR_NAMES:
        return True
    if not profile_scan:
        return False
    if is_scan_root:
        return False
    if path.name.lower() in _PROFILE_EXCLUDE_DIR_NAMES:
        return True
    norm = str(path).replace("/", "\\")
    return any(frag.replace("/", "\\") in norm for frag in _EXCLUDE_DIR_FRAGMENTS)


def _is_profile_scan_root(root: Path) -> bool:
    user_profile = os.environ.get("USERPROFILE", "")
    if not user_profile:
        return False
    try:
        return str(root.resolve()).lower().startswith(str(Path(user_profile).resolve()).lower())
    except OSError:
        return False


def _startup_roots() -> list[Path]:
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA", "")
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    if appdata:
        roots.append(
            Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        )
    roots.append(
        Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    )
    return [r for r in roots if r.exists()]


def _targeted_roots(target: str, repo_root: Path | None) -> list[Path]:
    root = repo_root or Path.cwd()
    if target == "startup":
        return _startup_roots() or [root / "scripts"]
    if target == "logs":
        return [root / "logs"]
    if target == "scripts":
        return [root / "scripts"]
    if target == "project":
        return [root]
    # default: project + scripts + logs + startup folders
    seen: set[Path] = set()
    ordered: list[Path] = []
    for candidate in [root, root / "scripts", root / "logs", *_startup_roots()]:
        resolved = candidate.resolve()
        if resolved not in seen and resolved.exists():
            seen.add(resolved)
            ordered.append(resolved)
    return ordered or [root]


def _iter_files(roots: list[Path]) -> Iterator[Path]:
    for root in roots:
        profile_scan = _is_profile_scan_root(root)
        resolved_root = root.resolve()
        if root.is_file():
            yield root
            continue
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            current = Path(dirpath)
            is_scan_root = current.resolve() == resolved_root
            dirnames[:] = [
                d
                for d in dirnames
                if not _should_exclude_dir(current / d, profile_scan=profile_scan)
            ]
            if _should_exclude_dir(current, profile_scan=profile_scan, is_scan_root=is_scan_root):
                dirnames.clear()
                continue
            for name in filenames:
                yield current / name


def safe_search(
    *,
    query: str,
    target: str = "project",
    repo_root: Path | None = None,
    max_seconds: float = _DEFAULT_MAX_SECONDS,
    max_files: int = _DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    """Search targeted paths with timeout and file-count caps."""
    start = time.monotonic()
    deadline = start + max(1.0, max_seconds)
    roots = _targeted_roots(target, repo_root)
    matches: list[dict[str, Any]] = []
    scanned = 0
    timed_out = False
    q = (query or "").lower()

    for path in _iter_files(roots):
        if time.monotonic() >= deadline:
            timed_out = True
            break
        if scanned >= max_files:
            timed_out = True
            break
        scanned += 1
        name = path.name
        if q and q not in name.lower() and q not in str(path).lower():
            continue
        if q and not fnmatch.fnmatch(name.lower(), f"*{q}*") and q not in str(path).lower():
            continue
        matches.append(
            {
                "path": str(path.resolve()),
                "name": name,
                "size_bytes": path.stat().st_size if path.is_file() else None,
            }
        )

    return {
        "schema_version": "safe_search.v1",
        "timestamp_utc": _now(),
        "query": query,
        "target": target,
        "roots": [str(r) for r in roots],
        "scanned_files": scanned,
        "match_count": len(matches),
        "timed_out": timed_out,
        "max_seconds": max_seconds,
        "max_files": max_files,
        "matches": matches,
        "limitations": [
            "Search is bounded and targeted — not a full user-profile scan.",
            "Matches are path observations only — not malware verdicts.",
        ],
    }
