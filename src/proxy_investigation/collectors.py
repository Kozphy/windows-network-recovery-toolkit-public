"""Read-only evidence collectors for localhost proxy drift investigations.

Module responsibility:
    Gather WinINET/WinHTTP proxy surfaces, localhost listener attribution, and dev-process
    correlation rows without mutating system state.

System placement:
    Called by ``workflow.run_proxy_investigation`` before ``hypotheses`` and ``validation``.
    Delegates registry/netstat work to ``src.proxy_guard`` primitives.

Input assumptions:
    Windows host with ``reg``/PowerShell/CIM available unless ``run`` is injected for tests.

Output guarantees:
    JSON-serializable dict blobs suitable for ``ProxyInvestigationResult`` fields.

Side effects:
    Subprocess and registry reads only; no writes.

Idempotency:
    Repeated calls reflect live machine state at call time (not idempotent across time).

Failure modes:
    Partial registry reads propagate as empty fields; malformed JSONL LKG files are skipped.

Audit Notes:
    * ``collect_dev_process_correlation`` may list command lines — treat output as sensitive.
    * Listener owners are correlation, not registry-writer proof (see ``ATTRIBUTION_LISTENER_ONLY``).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..core.models import registry_with_parsed
from ..proxy_guard.localhost_attribution import build_localhost_proxy_attribution
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.process_inventory import (
    capture_process_inventory,
    heuristic_proxy_actor_candidates,
)
from ..proxy_guard.registry import read_proxy_registry
from ..proxy_guard.snapshot_capture import capture_proxy_snapshot


def load_optional_before_snapshot(repo_root: Path) -> dict[str, Any] | None:
    """Load youngest known-good proxy snapshot if present (drift context only).

    Args:
        repo_root: Repository root containing ``reports/`` and ``logs/`` artifacts.

    Returns:
        Parsed snapshot dict, or ``None`` when no readable LKG file exists.

    Side effects:
        Reads ``reports/proxy_guard_lkg.json`` or tails ``logs/proxy_known_good_snapshots.jsonl``.

    Failure modes:
        Skips unreadable lines/files; does not raise on corrupt JSONL.
    """
    for candidate in (
        repo_root / "reports" / "proxy_guard_lkg.json",
        repo_root / "logs" / "proxy_known_good_snapshots.jsonl",
    ):
        if not candidate.is_file():
            continue
        try:
            if candidate.suffix == ".jsonl":
                last: dict[str, Any] | None = None
                for line in candidate.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(row, dict):
                        last = row.get("snapshot") if isinstance(row.get("snapshot"), dict) else row
                if last:
                    return last
            else:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except (OSError, json.JSONDecodeError):
            continue
    return None


def collect_proxy_state(*, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Capture HKCU WinINET, WinHTTP, environment, and git/npm proxy surfaces.

    Args:
        run: Injectable subprocess runner for tests.

    Returns:
        Dict with ``proxy_enable``, ``proxy_server``, ``winhttp``, ``environment``, etc.

    Side effects:
        Invokes registry reads and ``capture_proxy_snapshot``.
    """
    reg = read_proxy_registry(run=run)
    parsed = parse_proxy_server(reg.proxy_server)
    snap = capture_proxy_snapshot(registry_snapshot=reg, run=run)
    return {
        "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "proxy_enable": snap.proxy_enable,
        "proxy_server": snap.proxy_server,
        "proxy_override": snap.proxy_override,
        "auto_config_url": snap.auto_config_url,
        "auto_detect": snap.auto_detect,
        "winhttp": {
            "raw": snap.winhttp_proxy,
            "direct_access": snap.winhttp_direct_access,
            "proxy_server_literal": snap.winhttp_proxy_server_literal,
        },
        "environment": {
            "HTTP_PROXY": snap.user_http_proxy,
            "HTTPS_PROXY": snap.user_https_proxy,
            "ALL_PROXY": snap.user_all_proxy,
            "NO_PROXY": snap.user_no_proxy,
        },
        "git": {"http.proxy": snap.git_http_proxy, "https.proxy": snap.git_https_proxy},
        "npm": {"proxy": snap.npm_proxy, "https-proxy": snap.npm_https_proxy},
        "captured_at": snap.captured_at,
        "parsed_proxy": parsed.to_dict(),
        "registry_merge": registry_with_parsed(reg, parsed),
    }


def collect_listener_evidence(*, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Collect netstat/CIM listener correlation for the configured localhost proxy port.

    Args:
        run: Injectable subprocess runner for tests.

    Returns:
        Dict with ``localhost_attribution``, ``process_inventory``, and ``netstat_note``.

    Side effects:
        Subprocess/netstat-style probes via ``proxy_guard`` helpers.
    """
    reg = read_proxy_registry(run=run)
    parsed = parse_proxy_server(reg.proxy_server)
    block = build_localhost_proxy_attribution(reg, parsed, run=run)
    port = block.get("localhost_port")
    inventory = capture_process_inventory(proxy_localhost_port=port, run=run)
    return {
        "localhost_attribution": block,
        "process_inventory": inventory,
        "netstat_note": "Owners derived from netstat-ano and optional CIM enrichment.",
    }


def collect_dev_process_correlation(*, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Correlate Node/Electron/IDE processes with listener inventory (association only).

    Args:
        run: Injectable subprocess runner for tests.

    Returns:
        Dict with ``dev_process_rows``, ``heuristic_candidates``, ``listening_pids``, ``limitations``.

    Side effects:
        Process inventory capture; no termination or registry writes.

    Audit Notes:
        Output includes ``limitations`` reminding operators that correlation ≠ writer proof.
    """
    reg = read_proxy_registry(run=run)
    parsed = parse_proxy_server(reg.proxy_server)
    port = parsed.localhost_port
    inv = capture_process_inventory(proxy_localhost_port=port, run=run)
    rows = inv.get("process_rows") or []
    dev_rows: list[dict[str, Any]] = []
    from ..proxy_guard.attribution_model import ProxyActor

    actors: list[ProxyActor] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = str(r.get("process_name") or "").lower()
        if any(tok in name for tok in ("node", "electron", "code", "cursor", "npm", "python")):
            dev_rows.append(dict(r))
            try:
                pid = r.get("pid")
                if isinstance(pid, int):
                    actors.append(
                        ProxyActor(
                            pid=pid,
                            parent_pid=r.get("parent_pid") if isinstance(r.get("parent_pid"), int) else None,
                            process_name=r.get("process_name"),
                            image_path=r.get("executable_path"),
                            command_line=r.get("command_line"),
                            started_at=r.get("creation_time_utc"),
                        ),
                    )
            except (TypeError, ValueError):
                pass
    heuristic = [a.to_jsonable() for a in heuristic_proxy_actor_candidates(actors)]
    return {
        "dev_process_rows": dev_rows,
        "heuristic_candidates": heuristic,
        "listening_pids": inv.get("listening_pids") or [],
        "limitations": [
            "Process association detected — not proof of registry writer or malicious intent.",
        ],
    }
