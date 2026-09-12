#!/usr/bin/env python3
"""Scan repository for public-release privacy and hygiene risks."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".next",
    "dist",
    "build",
    "htmlcov",
    ".egg-info",
    ".ruff_cache",
}

ALLOWED_JSONL_PREFIXES = (
    "tests/fixtures/",
    "tests\\fixtures\\",
    "examples/",
    "examples\\",
    "windows_network_toolkit/examples/",
    "windows_network_toolkit\\examples\\",
    "demo_data/",
    "demo_data\\",
)

# Committed synthetic portfolio samples (see reports/.gitignore !sample_*.md).
ALLOWED_RUNTIME_ARTIFACT_PREFIXES = ("reports/sample_",)

ALLOWED_EMAIL_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "localhost",
    }
)

ALLOWED_IPS = frozenset({"127.0.0.1", "0.0.0.0", "8.8.8.8", "1.1.1.1"})

WINDOWS_USER_PATH = re.compile(r"[A-Za-z]:\\Users\\[^\\/\s\"']+", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
TOKEN_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"\b(?:api[_-]?key|secret|token|password)\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE
    ),
)

HIGH_RISK_RUNTIME_DIRS = (
    "logs",
    "reports",
    "platform_data",
    "platform_data_fleet_demo",
    "data/failure_blocks",
)
HIGH_RISK_ENV_NAMES = {".env", ".env.local"}

HIGH_RISK_CATEGORIES = frozenset(
    {
        "env_secrets",
        "jsonl_outside_demo",
        "runtime_artifacts",
        "operator_snapshot",
        "likely_secrets",
    }
)


def has_high_risk(findings: dict[str, list[str]]) -> bool:
    """Evaluate the has high risk condition.

    Args:
        findings: Value supplied by the caller for findings.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return any(findings.get(key) for key in HIGH_RISK_CATEGORIES)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _is_allowed_jsonl(rel: str) -> bool:
    return any(rel.startswith(prefix.replace("\\", "/")) for prefix in ALLOWED_JSONL_PREFIXES)


def _is_allowed_runtime_artifact(rel: str) -> bool:
    normalized = rel.replace("\\", "/")
    if normalized.endswith(".gitignore") or normalized.endswith(".gitkeep"):
        return True
    return any(
        normalized.startswith(prefix.replace("\\", "/"))
        for prefix in ALLOWED_RUNTIME_ARTIFACT_PREFIXES
    )


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIR_NAMES or name.endswith(".egg-info")


def git_tracked_files(root: Path) -> set[str]:
    """Provide git tracked files behavior for toolkit workflows.

    Args:
        root: Value supplied by the caller for root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    import subprocess

    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return set()
    if proc.returncode != 0:
        return set()
    return {line.strip().replace("\\", "/") for line in proc.stdout.splitlines() if line.strip()}


def scan_repo(
    root: Path,
    *,
    tracked_only: bool = False,
    tracked_files: set[str] | None = None,
) -> dict[str, list[str]]:
    """Scan repo for toolkit workflows.

    Args:
        root: Value supplied by the caller for root.
        tracked_only: Value supplied by the caller for tracked only.
        tracked_files: Value supplied by the caller for tracked files.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May read local system, file, or network state through configured providers.
    """
    findings: dict[str, list[str]] = defaultdict(list)

    tracked: set[str] | None = None
    if tracked_only:
        tracked = tracked_files if tracked_files is not None else git_tracked_files(root)

    candidates: list[Path]
    if tracked_only and tracked is not None:
        candidates = [root / rel for rel in sorted(tracked)]
    else:
        candidates = [p for p in root.rglob("*") if p.is_file()]

    for path in candidates:
        if not path.is_file():
            continue
        parts = path.parts
        if any(p in SKIP_DIR_NAMES or p.endswith(".egg-info") for p in parts):
            continue

        rel = _rel(path, root)
        if tracked_only and tracked is not None and rel not in tracked:
            continue
        name = path.name.lower()

        if name in HIGH_RISK_ENV_NAMES and not name.endswith(".example"):
            findings["env_secrets"].append(rel)
            continue

        if path.suffix.lower() == ".jsonl" and not _is_allowed_jsonl(rel):
            findings["jsonl_outside_demo"].append(rel)

        if path.suffix.lower() in {".log"} and "tests" not in parts:
            findings["log_files"].append(rel)

        for runtime_dir in HIGH_RISK_RUNTIME_DIRS:
            if rel.startswith(f"{runtime_dir}/") and not _is_allowed_runtime_artifact(rel):
                findings["runtime_artifacts"].append(rel)
                break

        if name == "last_known_good_proxy.json" and rel == "config/last_known_good_proxy.json":
            findings["operator_snapshot"].append(rel)

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if len(text) > 500_000:
            text = text[:500_000]

        for match in WINDOWS_USER_PATH.finditer(text):
            if "tests" in parts or rel.startswith("examples/"):
                continue
            snippet = match.group(0)
            lower = snippet.lower()
            if any(token in lower for token in ("alice", "demo", "public", "example")):
                continue
            findings["windows_user_paths"].append(f"{rel}: {snippet}")

        for match in EMAIL.finditer(text):
            domain = match.group(0).split("@", 1)[1].lower()
            if domain not in ALLOWED_EMAIL_DOMAINS:
                findings["email_addresses"].append(f"{rel}: {match.group(0)}")

        for match in PRIVATE_IP.finditer(text):
            ip = match.group(0)
            if "tests" in parts or "platform_core/privacy" in rel.replace("\\", "/"):
                continue
            if ip not in ALLOWED_IPS:
                findings["private_ip_addresses"].append(f"{rel}: {ip}")

        for pattern in TOKEN_PATTERNS:
            if pattern.search(text):
                if "tests" in parts or ".example" in name:
                    continue
                findings["likely_secrets"].append(f"{rel}: pattern {pattern.pattern[:40]}")

    for key in findings:
        findings[key] = sorted(set(findings[key]))
    return dict(findings)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Value supplied by the caller for argv.

    Returns:
        Process exit code or None when the command completes normally.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    parser = argparse.ArgumentParser(description="Audit repo before public GitHub release.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--strict", action="store_true", help="Treat medium findings as failures too."
    )
    parser.add_argument(
        "--tracked-only",
        action="store_true",
        help="Scan only git-tracked files (recommended before public push).",
    )
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="Also scan untracked working-tree files (local hygiene check).",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    tracked_only = args.tracked_only or not args.include_untracked
    findings = scan_repo(root, tracked_only=tracked_only)

    high_keys = HIGH_RISK_CATEGORIES
    medium_keys = {"windows_user_paths", "email_addresses", "private_ip_addresses", "log_files"}

    print(f"Public release audit: {root}")
    print("=" * 60)

    exit_code = 0
    for category in sorted(findings.keys()):
        items = findings[category]
        if not items:
            continue
        level = "HIGH" if category in high_keys else "MEDIUM"
        print(f"\n[{level}] {category} ({len(items)})")
        for item in items[:50]:
            print(f"  - {item}")
        if len(items) > 50:
            print(f"  ... and {len(items) - 50} more")
        if category in high_keys or (args.strict and category in medium_keys):
            exit_code = 1

    if not findings:
        print("\nNo findings — repo looks ready for a public release scan.")
    elif exit_code == 0:
        print("\nOnly medium findings (or none). Review before publishing.")
    else:
        print("\nHigh-risk findings detected. Fix or gitignore before public release.")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
