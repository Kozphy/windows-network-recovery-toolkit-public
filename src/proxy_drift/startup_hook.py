"""Shared Startup-folder hook helpers for proxy drift automation."""

from __future__ import annotations

import os
from pathlib import Path


def startup_folder() -> Path:
    """Return the current user's Windows Startup folder path.

    Args:
        None.

    Returns:
        Path to the Startup folder, derived from ``APPDATA`` or the user profile fallback.

    Side effects:
        Reads environment variables only."""
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    return (
        Path.home()
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )


def startup_hook_path(name: str) -> Path:
    """Build the Startup hook path for a named automation component.

    Args:
        name: Component or task name used as the ``.cmd`` filename stem.

    Returns:
        Path to the Startup hook command file.

    Side effects:
        Reads environment variables via ``startup_folder``."""
    return startup_folder() / f"{name}.cmd"


def write_startup_hook(*, name: str, lines: list[str]) -> Path:
    """Write a Startup-folder command hook.

    Args:
        name: Component or task name used as the ``.cmd`` filename stem.
        lines: Command lines to write using ASCII encoding.

    Returns:
        Path to the written hook file.

    Side effects:
        Creates the Startup folder if needed and writes the hook file.

    Audit Notes:
        Writing a Startup hook changes user logon behavior and must remain behind caller policy gates."""
    path = startup_hook_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def remove_startup_hook(name: str) -> bool:
    """Remove a Startup-folder command hook when present.

    Args:
        name: Component or task name used as the ``.cmd`` filename stem.

    Returns:
        ``True`` when a hook file was deleted; ``False`` when no file existed.

    Side effects:
        Deletes the matching Startup hook file if it exists."""
    path = startup_hook_path(name)
    if not path.exists():
        return False
    path.unlink()
    return True
