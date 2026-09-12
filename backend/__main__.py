"""Run the FastAPI backend with repo-root PYTHONPATH (use project .venv Python)."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    """Run the module command-line entry point.

    Args:
        None.

    Returns:
        None.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    os.environ.setdefault("PYTHONPATH", str(root))
    os.environ.setdefault("PLATFORM_FIXTURE_MODE", "1")

    host = os.environ.get("WNRT_API_HOST", "127.0.0.1")
    port = os.environ.get("WNRT_API_PORT", "8000")
    reload = os.environ.get("WNRT_API_RELOAD", "").lower() in {"1", "true", "yes"}
    # Public mirror / demo: prefer read-only fixture app unless explicitly overridden.
    app_path = os.environ.get("WNRT_API_APP", "").strip() or (
        "backend.public_app:app"
        if os.environ.get("WNRT_PUBLIC_API", "").lower() in {"1", "true", "yes"}
        else "backend.main:app"
    )

    import uvicorn

    try:
        uvicorn.run(
            app_path,
            host=host,
            port=int(port),
            reload=reload,
            factory=False,
        )
    except OSError as exc:
        if getattr(exc, "winerror", None) == 10048 or "address already in use" in str(exc).lower():
            print(
                f"\nPort {port} is already in use on {host}.\n"
                f"  Option A — use another port:\n"
                f'    $env:WNRT_API_PORT="8001"; python -m backend\n'
                f"  Option B — find and stop the listener:\n"
                f'    netstat -ano | findstr ":{port}"\n'
                f"    Stop-Process -Id <PID> -Force\n",
                file=sys.stderr,
            )
        raise


if __name__ == "__main__":
    main()
