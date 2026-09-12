"""Populate three synthetic endpoints for dashboard / metrics demos (no host mutation).

Module responsibility:
    Append deterministic JSONL rows (endpoints, failure events, signals, audit, attribution context) so operators
    can **rehearse** ``GET /platform/*`` and Next.js ``/platform`` without running Windows collectors.

System placement:
    Invoked as ``python -m platform_core.demo_fleet``; optional import of :func:`populate_fleet` from tests.

Key invariants:
    * Synthetic ``endpoint_id`` strings are fixed literals—never collide with hashed identities from real agents when
      operators merge directories manually (prefer isolated ``--data-dir``).
    * Writes target caller-supplied directory only—never touches repository ``platform_data/`` unless explicitly chosen.

Side effects:
    Creates/overwrites JSONL files under *target*; sets ``PLATFORM_DATA_DIR`` in CLI ``main()`` process env.

Idempotency:
    Without ``--reset``, appends duplicate-looking rows (metrics counters inflate)—use ``--reset`` for clean demos.

Failure modes:
    Disk permission errors propagate as :exc:`OSError`.

Audit Notes:
    Rows are labeled ``fleet_demo`` / synthetic summaries—do not ship these shards as forensic evidence of production incidents.

Run::

    python -m platform_core.demo_fleet --data-dir platform_data_fleet_demo

CLI ``main()`` overrides ``PLATFORM_DATA_DIR`` for the process lifetime so :func:`platform_core.metrics.compute_platform_metrics`
prints excerpts aligned with the seeded corpus.
"""

from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from platform_core.metrics import compute_platform_metrics
from platform_core.models import utc_now_iso
from platform_core.storage import append_jsonl


def _line(path: Path, row: dict) -> None:
    """Append one JSON object via :func:`~platform_core.storage.append_jsonl`."""

    append_jsonl(path, row)


def populate_fleet(target: Path, *, reset: bool = False) -> None:
    """Write JSONL shards under *target* mimicking a tiny three-endpoint fleet.

    Args:
        target: Directory receiving ``*.jsonl`` files consumed by :mod:`platform_core.metrics` and routers.
        reset: When ``True``, unlink listed shard files before append so KPI runs stay interpretable.

    Returns:
        ``None``.

    Raises:
        ``OSError`` when directories/files cannot be written.

    Side effects:
        UTF-8 append-only writes per shard; does **not** invoke subprocess or network probes.

    Recovery guidance:
        Delete *target* entirely or rerun with ``reset=True`` when duplicate seeds confuse dashboards.
    """

    target.mkdir(parents=True, exist_ok=True)
    files = [
        "endpoints.jsonl",
        "failure_events.jsonl",
        "snapshots.jsonl",
        "platform_signals.jsonl",
        "audit.jsonl",
        "attribution_context.jsonl",
    ]
    if reset:
        for name in files:
            p = target / name
            if p.is_file():
                p.unlink()

    now = utc_now_iso()

    ep_healthy = "0f00fleeth000000000000000000001"
    ep_drift = "0f00fleetcd000000000000000000002"
    ep_suspicious = "0f00flectxd000000000000000000003"

    ev_drift = str(uuid.uuid4())
    ev_bad = str(uuid.uuid4())

    _line(
        target / "endpoints.jsonl",
        {
            "endpoint_id": ep_healthy,
            "os_family": "Windows",
            "os_version": "11",
            "agent_version": "demo-fleet",
            "created_at": now,
            "last_seen_at": now,
        },
    )
    _line(
        target / "endpoints.jsonl",
        {
            "endpoint_id": ep_drift,
            "os_family": "Windows",
            "os_version": "10",
            "agent_version": "demo-fleet",
            "created_at": now,
            "last_seen_at": now,
        },
    )
    _line(
        target / "endpoints.jsonl",
        {
            "endpoint_id": ep_suspicious,
            "os_family": "Windows",
            "os_version": "11",
            "agent_version": "demo-fleet",
            "created_at": now,
            "last_seen_at": now,
        },
    )

    _line(
        target / "failure_events.jsonl",
        {
            "event_id": ev_drift,
            "endpoint_id": ep_drift,
            "failure_block_id": "fb-drift",
            "severity": "medium",
            "category": "proxy",
            "confidence": 0.72,
            "first_seen_at": now,
            "last_seen_at": now,
            "status": "open",
            "summary": "ProxyServer drift toward loopback listener",
            "recommended_action_key": "reset_proxy",
        },
    )
    _line(
        target / "failure_events.jsonl",
        {
            "event_id": ev_bad,
            "endpoint_id": ep_suspicious,
            "failure_block_id": "fb-suspicious",
            "severity": "high",
            "category": "proxy",
            "confidence": 0.85,
            "first_seen_at": now,
            "last_seen_at": now,
            "status": "open",
            "summary": "Unknown localhost proxy with suspicious path hint (fixture)",
            "recommended_action_key": "inspect_proxy",
        },
    )

    _line(
        target / "snapshots.jsonl",
        {
            "endpoint_id": ep_drift,
            "collected_at": now,
            "network_state": {"ping_ip_ok": True},
            "proxy_state": {"winhttp_direct": True, "proxy_server_line_present": True},
            "dns_state": {"nslookup_ok": True},
            "tcp_state": {"curl_https_ok": True},
            "browser_path_state": {},
            "process_clues": {},
            "raw_data_redacted": True,
        },
    )

    _line(
        target / "platform_signals.jsonl",
        {"kind": "heartbeat", "endpoint_id": ep_healthy},
    )
    _line(
        target / "platform_signals.jsonl",
        {"kind": "proxy_registry_change", "endpoint_id": ep_drift, "confidence": 0.61},
    )
    _line(
        target / "platform_signals.jsonl",
        {"kind": "unknown_actor_marker", "endpoint_id": ep_suspicious, "unknown_actor": True},
    )

    _line(
        target / "audit.jsonl",
        {
            "audit_id": str(uuid.uuid4()),
            "actor": "fleet_demo",
            "action": "seed",
            "target_type": "fleet",
            "target_id": ep_suspicious,
            "decision": "info",
            "rationale": "demo_fleet synthetic population",
            "timestamp": now,
        },
    )

    _line(
        target / "attribution_context.jsonl",
        {
            "event_id": ev_drift,
            "registry_context": {
                "before": {"ProxyEnable": "0"},
                "after": {"ProxyEnable": "1", "ProxyServer": "127.0.0.1:8899"},
            },
            "listeners": [{"port": "8899", "address": "127.0.0.1"}],
            "sysmon": [
                {
                    "EventID": "13",
                    "Image": "C:\\FleetDemo\\trusted_updater.exe",
                    "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable",
                },
            ],
        },
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry: parse args, seed fleet, print metrics excerpt JSON to stdout.

    Returns:
        Process exit code ``0``.

    Side effects:
        Sets ``PLATFORM_DATA_DIR`` env var and writes JSONL under chosen directory.
    """

    p = argparse.ArgumentParser(
        description="Seed fake fleet JSONL for dashboards (read-only demo data)."
    )
    p.add_argument(
        "--data-dir",
        "--output",
        type=Path,
        default=None,
        dest="data_dir",
        help="Output directory (default ./platform_data_fleet_demo). Alias: --output.",
    )
    p.add_argument(
        "--reset", action="store_true", help="Delete known demo JSONL shards before appending."
    )
    p.add_argument("--endpoints", type=int, default=None, help="Use fleet_simulation when set (e.g. 100).")
    p.add_argument("--incidents", type=int, default=None, help="Cap incidents when using --endpoints (e.g. 20).")
    ns = p.parse_args(argv)

    root = ns.data_dir or (Path.cwd() / "platform_data_fleet_demo")
    if ns.endpoints is not None:
        from platform_core.fleet_simulation import run_fleet_simulation

        os.environ["PLATFORM_DATA_DIR"] = str(root.resolve())
        summary = run_fleet_simulation(
            scenario="proxy-drift",
            endpoints=ns.endpoints,
            incidents=ns.incidents,
            out_dir=root,
        )
        metrics = compute_platform_metrics(platform_root=root.resolve())
        print(json.dumps({"fleet": summary, "metrics_excerpt": metrics}, indent=2))
        return 0
    os.environ["PLATFORM_DATA_DIR"] = str(root.resolve())
    populate_fleet(root, reset=bool(ns.reset))

    metrics = compute_platform_metrics(platform_root=root.resolve())
    print(
        json.dumps(
            {
                "data_dir": str(root),
                "metrics_excerpt": {k: metrics[k] for k in sorted(metrics) if k != "signals_file"},
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
