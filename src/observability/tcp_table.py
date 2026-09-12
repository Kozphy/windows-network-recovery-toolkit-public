"""Collect ``netstat -ano`` text and summarize TCP ports for snapshots.

Separation from ``src.attribution`` keeps subprocess capture here while parsing stays reusable
across fixtures.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from typing import Any

from ..attribution.port_owner import netstat_listen_rows


def capture_netstat_ano(
    *,
    run: Callable[..., Any] = subprocess.run,
) -> tuple[int, str]:
    """Run ``netstat -ano`` and return ``(exit_code, stdout+stderr)``.

    Note:
        ``OSError``/timeout exceptions surface as synthetic exit code ``1`` plus error text (no bubbling).

    Audit Notes:
        Elevated shells can surface additional adapters; compare runs only when probing the same privilege level.
    """
    try:
        proc = run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=35,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


_TCP_ROW = re.compile(
    r"^\s*TCP\s+(?P<local>\S+:\d+)\s+(?P<remote>\S+:\d+)\s+(?P<state>\S+)",
    re.IGNORECASE,
)


def _local_port(addr: str) -> int | None:
    if ":" not in addr:
        return None
    _, _, p = addr.rpartition(":")
    try:
        return int(p)
    except ValueError:
        return None


def established_counts_by_local_port(netstat_text: str) -> dict[int, int]:
    """Count ESTABLISHED TCP rows by numeric local port (IPv4 or bracketed IPv6)."""
    counts: dict[int, int] = {}
    for line in netstat_text.splitlines():
        m = _TCP_ROW.match(line.strip())
        if not m:
            continue
        if m.group("state").upper() != "ESTABLISHED":
            continue
        port = _local_port(m.group("local"))
        if port is None:
            continue
        counts[port] = counts.get(port, 0) + 1
    return counts


def top_n_ports(counts: dict[int, int], n: int = 12) -> tuple[dict[str, int | float], ...]:
    """Return top ``n`` ports as ``{port, established_count}`` dicts."""
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    return tuple({"port": p, "established_count": c} for p, c in items)


def localhost_listen_ports(netstat_text: str) -> tuple[int, ...]:
    """Return sorted unique ports listening on ``127.*`` or ``::1`` hosts."""
    rows = netstat_listen_rows(netstat_text)
    ports: list[int] = []
    seen: set[int] = set()
    for host, port, _pid in rows:
        hl = host.lower().strip("[]")
        loopback = hl.startswith("127.") or hl == "::1"
        if loopback:
            if port not in seen:
                seen.add(port)
                ports.append(port)
    return tuple(sorted(ports))
