"""Orchestrate ``LiveNetworkSnapshot`` assembly from collectors + Proxy Guard + sockets.

Engineering Notes:
    Delegates heavy subprocess usage to existing diagnostics collector to avoid duplicating
    ICMP/DNS/curl probes while extending with ``netstat`` / ``tasklist`` correlation.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..core.models import LiveNetworkSnapshot
from ..core.time_utils import utc_now_iso
from ..diagnostics.collector import collect_features
from ..proxy_guard.owner import resolve_localhost_proxy_owners
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.registry import read_proxy_registry
from .process_table import capture_tasklist_csv, extract_interesting_processes
from .tcp_table import (
    capture_netstat_ano,
    established_counts_by_local_port,
    localhost_listen_ports,
    top_n_ports,
)


def build_live_network_snapshot(
    *,
    repo_root: Path | None = None,
    run: Callable[..., Any] = subprocess.run,
) -> tuple[LiveNetworkSnapshot, tuple[dict[str, str], ...]]:
    """Collect registry, socket, process, and probe signals into one frozen snapshot.

    Args:
        repo_root: Reserved for API parity; currently ignored (see ``del`` below).
        run: Injectable ``subprocess.run`` for tests.

    Returns:
        ``LiveNetworkSnapshot`` plus command label list mirroring legacy collector metadata.

    Side effects:
        Executes ``collect_features`` subprocess graph, ``reg query``, ``netstat``, ``tasklist``,
        and optional PowerShell CIM calls during owner resolution.

    Idempotency:
        Semantically idempotent for stable host state; each call issues fresh probes.

    Audit Notes:
        Pair written JSON with ``logs/network_snapshots.jsonl`` rows for traceability.
    """
    del repo_root  # reserved for parity with legacy collector signature
    features, meta = collect_features(repo_root=None)
    commands_executed: list[dict[str, str]] = list(meta.get("commands_executed") or [])
    commands_executed.append({"label": "netstat_ano", "cmd": "netstat -ano"})
    commands_executed.append({"label": "tasklist_csv", "cmd": "tasklist /FO CSV /NH"})

    reg = read_proxy_registry(run=run)
    parsed = parse_proxy_server(reg.proxy_server)

    ncode, nst = capture_netstat_ano(run=run)
    if ncode != 0:
        nst = ""

    tcode, tcsv = capture_tasklist_csv(run=run)
    interesting = extract_interesting_processes(tcsv if tcode == 0 else "")

    owners, onotes = resolve_localhost_proxy_owners(parsed.localhost_port, run=run)

    ec = established_counts_by_local_port(nst)
    top_ports = top_n_ports(ec, n=12)
    llisten = localhost_listen_ports(nst)

    perm_notes_list = list(onotes)

    snapshot = LiveNetworkSnapshot(
        generated_at_utc=utc_now_iso(),
        feature_vector=features,
        proxy_registry=reg,
        parsed_proxy=parsed,
        port_owners=owners,
        localhost_listen_ports=llisten,
        interesting_processes=interesting,
        tcp_top_ports=top_ports,
        commands_executed=tuple(commands_executed),
        permission_notes=tuple(perm_notes_list),
    )
    return snapshot, tuple(commands_executed)
