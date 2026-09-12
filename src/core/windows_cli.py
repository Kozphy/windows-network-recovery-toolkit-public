"""Shared guards for Windows-only CLI entrypoints."""

from __future__ import annotations

import platform
import sys


def exit_code_if_not_windows(feature: str) -> int | None:
    """Return ``2`` when the current OS is not Windows (after printing to stderr).

    Args:
        feature: Short human-readable command or surface name for the error line.

    Returns:
        ``None`` if Windows, else ``2``.
    """
    if platform.system() == "Windows":
        return None
    print(f"{feature}: this command requires Windows.", file=sys.stderr)
    return 2
