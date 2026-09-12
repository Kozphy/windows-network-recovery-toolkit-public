"""CLI handler for ``python -m src proxy-linux-snapshot``."""

from __future__ import annotations

import json
import platform
import sys
from argparse import Namespace

from .linux_proxy_snapshot import collect_linux_proxy_snapshot


def cmd_proxy_linux_snapshot(args: Namespace) -> int:
    """Run the proxy linux snapshot command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    if platform.system().lower() not in {"linux", "darwin"}:
        print(
            "proxy-linux-snapshot is intended for Linux hosts (and macOS for env-only reads). "
            "Use proxy-snapshot on Windows.",
            file=sys.stderr,
        )
        return 2

    snap = collect_linux_proxy_snapshot(
        skip_optional_cli=bool(getattr(args, "skip_optional_cli", False)),
    )
    payload = snap.to_jsonable()

    if bool(getattr(args, "emit_json", False)):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(f"Captured: {payload['captured_at_utc']}")
    print(f"Distro: {payload['linux_distro']}  WSL: {payload['wsl']}")
    print(f"Proxy configured: {payload['proxy_configured']}")
    if payload["environment"]:
        print("Environment:")
        for k, v in sorted(payload["environment"].items()):
            print(f"  {k}={v}")
    if payload["etc_environment"]:
        print("/etc/environment:")
        for k, v in sorted(payload["etc_environment"].items()):
            print(f"  {k}={v}")
    if payload["gsettings"]:
        gs = {k: v for k, v in payload["gsettings"].items() if v and v not in ("''", '""', "none")}
        if gs:
            print("gsettings:")
            for k, v in sorted(gs.items()):
                print(f"  {k}={v}")
    if payload["networkmanager"].get("proxy-method") or payload["networkmanager"].get("proxy"):
        print("NetworkManager:")
        for k, v in payload["networkmanager"].items():
            if v:
                print(f"  {k}={v}")
    if payload["apt_proxy_lines"]:
        print("apt proxy:")
        for line in payload["apt_proxy_lines"]:
            print(f"  {line}")
    if payload["limitations"]:
        print("Limitations:", ", ".join(payload["limitations"]))
    return 0
