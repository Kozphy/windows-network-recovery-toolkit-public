"""Map localhost proxy numeric ports to current LISTENING netstat snapshots."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from ..attribution.port_owner import netstat_listen_rows, owners_for_port
from ..observability.tcp_table import capture_netstat_ano


def localhost_port_listen_state(port: int | None, *, run: Callable[..., Any] = subprocess.run) -> bool | None:
    """Return ``True`` when *port* has a LISTENING row; ``False`` when query succeeded but absent.

    ``None`` denotes inconclusive probes (elevated tooling failures).
    """
    if port is None:
        return None
    code, text = capture_netstat_ano(run=run)
    if code != 0:
        return None
    rows = netstat_listen_rows(text)
    return bool(owners_for_port(rows, int(port)))
