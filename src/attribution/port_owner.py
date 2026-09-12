"""Parse loopback listener tables from ``netstat``/``tasklist`` text (no subprocess I/O).

Input assumptions:
    Caller supplies raw Windows console text (CRLF tolerated). Only TCP ``LISTENING`` rows
    participate in listener maps; malformed lines are skipped silently.

Output guarantees:
    ``netstat_listen_rows`` returns host/port/pid triples with integer ports; PID 0 is treated
    literally if present in source text.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable

_TCP_LISTEN = re.compile(
    r"^\s*TCP\s+(?P<local>\S+)\s+\S+\s+LISTENING\s+(?P<pid>\d+)",
    re.IGNORECASE,
)


def _split_host_port(loc: str) -> tuple[str, int] | None:
    loc = loc.strip()
    if loc.startswith("["):
        # [::]:443
        m = re.match(r"^\[(?P<h>[^\]]+)\]:(?P<p>\d+)$", loc)
        if not m:
            return None
        return m.group("h"), int(m.group("p"))
    if ":" not in loc:
        return None
    host, _, port_s = loc.rpartition(":")
    try:
        return host.strip(), int(port_s)
    except ValueError:
        return None


def netstat_listen_rows(text: str) -> list[tuple[str, int, int]]:
    """Parse ``netstat -ano`` stdout into ``(local_address, port, pid)`` tuples.

    Only LISTENING TCP rows are returned. Parsing is forgiving of spacing.
    """
    out: list[tuple[str, int, int]] = []
    for line in text.splitlines():
        m = _TCP_LISTEN.match(line.strip())
        if not m:
            continue
        hp = _split_host_port(m.group("local"))
        if hp is None:
            continue
        host, port = hp
        pid = int(m.group("pid"))
        out.append((host, port, pid))
    return out


def owners_for_port(rows: Iterable[tuple[str, int, int]], port: int) -> list[int]:
    """Return distinct PIDs listening on ``port`` (any local bind address)."""
    seen: set[int] = set()
    pids: list[int] = []
    for _host, prt, pid in rows:
        if prt != port:
            continue
        if pid in seen:
            continue
        seen.add(pid)
        pids.append(pid)
    return pids


def parse_tasklist_csv_data(text: str) -> dict[int, str]:
    """Map PID -> Image Name from ``tasklist /FO CSV /NH`` style output."""
    mp: dict[int, str] = {}
    reader = csv.reader(io.StringIO(text.strip()))
    for row in reader:
        if len(row) < 2:
            continue
        name = row[0].strip('"')
        try:
            pid = int(row[1].strip('"'))
        except ValueError:
            continue
        mp[pid] = name
    return mp
