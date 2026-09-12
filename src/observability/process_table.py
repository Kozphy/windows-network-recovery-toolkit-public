"""Thin ``tasklist`` capture plus heuristic CSV filtering for tooling-heavy processes."""

from __future__ import annotations

import csv
import io
import subprocess
from collections.abc import Callable
from typing import Any


def capture_tasklist_csv(*, run: Callable[..., Any] = subprocess.run) -> tuple[int, str]:
    """Return ``tasklist /FO CSV /NH`` combined output for CSV parsers."""
    try:
        proc = run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=35,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


_INTERESTING = (
    "node",
    "python",
    "pwsh",
    "powershell",
    "cmd",
    "cursor",
    "code",
    "vpn",
    "openvpn",
    "wireguard",
    "warp",
    "clash",
    "mitm",
    "fiddler",
    "proxifier",
    "mcp",
)


def extract_interesting_processes(tasklist_csv: str, *, limit: int = 40) -> tuple[dict[str, str], ...]:
    """Return up to ``limit`` CSV rows matching substring tokens in executable image paths.

    Constraints:
        Heuristic-only; omission does not imply a host is proxy-free.

    Failure modes:
        Malformed CSV rows skip quietly without raising.
    """
    out: list[dict[str, str]] = []
    reader = csv.reader(io.StringIO(tasklist_csv.strip()))
    for row in reader:
        if len(row) < 5:
            continue
        image = row[0].strip('"').lower()
        if not any(token in image for token in _INTERESTING):
            continue
        out.append(
            {
                "image": row[0].strip('"'),
                "pid": row[1].strip('"'),
                "mem_usage": row[4].strip('"'),
            },
        )
        if len(out) >= limit:
            break
    return tuple(out)
