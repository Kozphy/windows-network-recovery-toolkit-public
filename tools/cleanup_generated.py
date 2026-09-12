#!/usr/bin/env python3
"""Remove local generated artifacts (logs, reports, platform_data) — dry-run by default."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

DEFAULT_TARGETS = (
    "logs",
    "reports",
    "platform_data",
    "platform_data_fleet_demo",
    "data/failure_blocks",
    ".pytest_cache",
    "htmlcov",
)


def _clean(path: Path, *, apply: bool) -> list[str]:
    removed: list[str] = []
    if not path.exists():
        return removed
    if path.is_file():
        if apply:
            path.unlink(missing_ok=True)
        removed.append(str(path))
        return removed
    for child in path.rglob("*"):
        if child.is_file() and apply:
            child.unlink(missing_ok=True)
    if apply:
        shutil.rmtree(path, ignore_errors=True)
    removed.append(str(path))
    return removed


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Value supplied by the caller for argv.

    Returns:
        Process exit code or None when the command completes normally.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    parser = argparse.ArgumentParser(description="Clean generated runtime directories.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--apply", action="store_true", help="Actually delete (default is dry-run preview)."
    )
    parser.add_argument("--targets", nargs="*", default=list(DEFAULT_TARGETS))
    args = parser.parse_args(argv)

    root = args.root.resolve()
    planned: list[str] = []
    for name in args.targets:
        planned.extend(_clean(root / name, apply=args.apply))

    mode = "REMOVED" if args.apply else "Would remove"
    for item in planned:
        print(f"{mode}: {item}")
    if not planned:
        print("Nothing to clean.")
    elif not args.apply:
        print("\nRe-run with --apply to delete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
