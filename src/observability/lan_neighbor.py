"""Read-only LAN neighbor table collection (ARP cache and Get-NetNeighbor).

Module responsibility:
    Parse Windows neighbor tables into normalized IP/MAC device rows for inventory
    and watch pipelines.

System placement:
    Called by ``windows_network_toolkit.diagnostics.lan_privacy.collectors`` and
    ``lan-inventory`` / ``lan-watch`` CLI paths.

Key invariants:
    * Read-only subprocess calls — no registry or network mutation.
    * Returns empty devices with ``limitations`` on non-Windows hosts unless ``inject`` is set.
    * ARP cache reflects recent neighbors only, not a full subnet scan.

Side effects:
    * Spawns ``arp -a`` and/or PowerShell ``Get-NetNeighbor`` on Windows.
"""

from __future__ import annotations

import platform
import re
import subprocess
from collections.abc import Callable
from typing import Any

_ARP_LINE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{11,17})\s+(\w+)",
    re.MULTILINE,
)


def _parse_arp_output(text: str) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in _ARP_LINE.finditer(text):
        ip, mac, iface = match.groups()
        mac_norm = mac.replace("-", ":").upper()
        if ip in seen:
            continue
        seen.add(ip)
        devices.append(
            {
                "ip": ip,
                "mac": mac_norm,
                "interface": iface,
                "source": "arp_cache",
            }
        )
    return devices


def collect_arp_neighbors(
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Collect neighbors from ``arp -a`` (read-only)."""
    if inject is not None:
        return {"ok": True, "devices": inject, "method": "inject", "limitations": []}

    if platform.system().lower() != "windows":
        return {
            "ok": False,
            "devices": [],
            "method": "arp",
            "unsupported_platform": True,
            "limitations": ["ARP collection requires Windows or fixture inject."],
        }

    run_fn = run or subprocess.run
    try:
        proc = run_fn(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        devices = _parse_arp_output(text)
        return {
            "ok": proc.returncode == 0 or bool(devices),
            "devices": devices,
            "method": "arp",
            "limitations": [
                "ARP cache shows recent neighbors only — not a full subnet inventory.",
            ],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "devices": [],
            "method": "arp",
            "error": str(exc),
            "limitations": ["ARP collection failed."],
        }


def collect_net_neighbors_powershell(
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 20.0,
    inject: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Collect neighbors via PowerShell Get-NetNeighbor (read-only)."""
    if inject is not None:
        return {"ok": True, "devices": inject, "method": "inject", "limitations": []}

    if platform.system().lower() != "windows":
        return {
            "ok": False,
            "devices": [],
            "method": "netneighbor",
            "unsupported_platform": True,
            "limitations": ["Get-NetNeighbor requires Windows or fixture inject."],
        }

    ps = (
        "Get-NetNeighbor -AddressFamily IPv4 | "
        "Where-Object { $_.State -ne 'Unreachable' } | "
        "Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | "
        "ConvertTo-Json -Compress"
    )
    run_fn = run or subprocess.run
    try:
        proc = run_fn(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        import json

        raw = (proc.stdout or "").strip()
        devices: list[dict[str, Any]] = []
        if raw:
            parsed = json.loads(raw)
            rows = parsed if isinstance(parsed, list) else [parsed]
            for row in rows:
                ip = row.get("IPAddress") or row.get("ip")
                mac = row.get("LinkLayerAddress") or row.get("mac") or ""
                if not ip:
                    continue
                devices.append(
                    {
                        "ip": str(ip),
                        "mac": str(mac).replace("-", ":").upper(),
                        "interface": row.get("InterfaceAlias") or "",
                        "state": row.get("State") or "",
                        "source": "net_neighbor",
                    }
                )
        return {
            "ok": bool(devices) or proc.returncode == 0,
            "devices": devices,
            "method": "netneighbor",
            "limitations": [
                "Neighbor table shows L2 reachability — not hostname or vendor proof.",
            ],
        }
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "devices": [],
            "method": "netneighbor",
            "error": str(exc),
            "limitations": ["Get-NetNeighbor collection failed."],
        }


def collect_lan_neighbors(
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 20.0,
    inject: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Merge ARP and NetNeighbor results (dedupe by IP)."""
    if inject is not None:
        return {"ok": True, "devices": inject, "limitations": []}

    arp = collect_arp_neighbors(run=run, timeout=timeout)
    net = collect_net_neighbors_powershell(run=run, timeout=timeout)
    merged: dict[str, dict[str, Any]] = {}
    for dev in (arp.get("devices") or []) + (net.get("devices") or []):
        ip = dev.get("ip")
        if not ip:
            continue
        if ip not in merged or (dev.get("mac") and not merged[ip].get("mac")):
            merged[ip] = dev
    limitations = list(arp.get("limitations") or []) + list(net.get("limitations") or [])
    return {
        "ok": arp.get("ok") or net.get("ok"),
        "devices": list(merged.values()),
        "limitations": limitations,
    }
