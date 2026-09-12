"""Remediation helpers — preview wiring only; execution lives in backend allowlist."""

from __future__ import annotations

from pathlib import Path

from .remediation_registry import list_script_basenames


def repo_scripts_dir(base: Path | None = None) -> Path:
    """Return absolute ``scripts/`` directory (repository root)."""
    if base is None:
        base = Path(__file__).resolve().parent.parent
    return base / "scripts"


def allowlisted_script(script_basename: str, repo_root: Path | None = None) -> Path | None:
    """Resolve script path if basename is in allowlist and file exists."""
    if script_basename not in _ALLOWLIST:
        return None
    p = repo_scripts_dir(repo_root) / script_basename
    if p.is_file():
        return p
    return None


_EXTRA_DIAGNOSTIC_SCRIPTS: frozenset[str] = frozenset(
    {
        "auto_diagnose.bat",
        "proxy_status.bat",
    },
)
_ALLOWLIST: frozenset[str] = frozenset(list_script_basenames()) | _EXTRA_DIAGNOSTIC_SCRIPTS
