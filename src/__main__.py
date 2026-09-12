"""Entry point for ``python -m src`` (Windows Network Recovery Toolkit decision CLI).

Module responsibility:
    Expose the stdlib-first ``python -m src`` dispatcher implemented in :mod:`src.cli` while preserving identical
    argv parsing and exit-code semantics as invoking ``main()`` directly.

System placement:
    Thin shim only—feature wiring, auditing, and subcommands remain in sibling modules imported by ``cli``.

Side effects:
    None at import time; executing this module invokes :func:`~src.cli.main`, which performs whatever the active
    subparser demands (often subprocess probes and append-only logs).

Raises:
    :class:`SystemExit` with the CLI return code via ``raise SystemExit(main())``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _venv_python(repo_root: Path) -> Path | None:
    if sys.platform == "win32":
        candidate = repo_root / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = repo_root / ".venv" / "bin" / "python"
    return candidate if candidate.is_file() else None


def _bootstrap_runtime() -> None:
    """Re-exec with repo ``.venv`` when system Python lacks installed project deps."""
    try:
        import pydantic  # noqa: F401
    except ModuleNotFoundError:
        repo_root = Path(__file__).resolve().parent.parent
        venv_py = _venv_python(repo_root)
        if venv_py is not None:
            os.execv(str(venv_py), [str(venv_py), "-m", "src", *sys.argv[1:]])
        print(
            "Missing Python dependencies (pydantic). From the repo root, run:\n"
            "  python -m venv .venv\n"
            "  .\\.venv\\Scripts\\pip install -r requirements.txt\n"
            "Or use the launcher:\n"
            "  .\\scripts\\wnt-src.ps1 proxy-boot-trace --duration 180 --interval 2",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


_bootstrap_runtime()

from .cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
