"""Read-only DNS health observations for endpoint browsers (not DNS malware proof)."""

from __future__ import annotations

import ipaddress
import subprocess
from collections.abc import Callable
from typing import Any

_SCHEMA = "dns_health.v1"

LIMITATIONS = [
    "Observation only — does not prove which process configured DNS.",
    "Corporate NRPT / DoH may override adapter DNS; browser errors can still occur.",
    "DNS_PROBE_FINISHED_BAD_CONFIG is a browser signal, not a Windows API code.",
]


def _same_slash24(a: str, b: str) -> bool:
    try:
        net_a = ipaddress.ip_network(f"{a}/24", strict=False)
        ip_b = ipaddress.ip_address(b)
        return ip_b in net_a
    except ValueError:
        return False


def assess_dns_mismatch(
    *,
    interface_ipv4: str | None,
    gateway: str | None,
    dns_servers: list[str],
) -> dict[str, Any]:
    """Flag common BAD_CONFIG patterns: primary DNS off-subnet vs Wi-Fi IPv4."""
    servers = [s for s in dns_servers if s]
    primary = servers[0] if servers else None
    off_subnet = False
    if interface_ipv4 and primary:
        # Only flag private primary DNS that is not on the interface /24.
        try:
            primary_ip = ipaddress.ip_address(primary)
            if primary_ip.is_private and not _same_slash24(interface_ipv4, primary):
                off_subnet = True
        except ValueError:
            off_subnet = False

    label = "DNS_OK"
    rationale = "No off-subnet private primary DNS detected."
    if not servers:
        label = "DNS_UNSPECIFIED"
        rationale = "No IPv4 DNS servers reported for the interface."
    elif off_subnet:
        label = "DNS_PRIMARY_OFF_SUBNET"
        rationale = (
            f"Primary DNS {primary} is not on the same /24 as interface {interface_ipv4}; "
            "browsers may show DNS_PROBE_FINISHED_BAD_CONFIG."
        )

    return {
        "schema_version": _SCHEMA,
        "classification": label,
        "rationale": rationale,
        "interface_ipv4": interface_ipv4,
        "gateway": gateway,
        "dns_servers": servers,
        "primary_dns": primary,
        "primary_off_subnet": off_subnet,
        "recommended_action": (
            "Run fix-dns.cmd (elevated) to set gateway + 1.1.1.1 + 8.8.8.8, then refresh browser."
            if off_subnet or label == "DNS_UNSPECIFIED"
            else "No DNS adapter change recommended from this heuristic."
        ),
        "limitations": list(LIMITATIONS),
    }


def collect_wifi_dns_snapshot(
    *,
    interface_alias: str = "Wi-Fi",
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Best-effort Windows read of Wi-Fi IPv4 / gateway / DNS via PowerShell."""
    subprocess_run = run if run is not None else subprocess.run
    if not interface_alias:
        return assess_dns_mismatch(interface_ipv4=None, gateway=None, dns_servers=[])

    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$cfg = Get-NetIPConfiguration -InterfaceAlias '{interface_alias}'
if (-not $cfg) {{ Write-Output 'MISSING'; exit 0 }}
$ip = [string]$cfg.IPv4Address.IPAddress
$gw = [string]$cfg.IPv4DefaultGateway.NextHop
$dns = (Get-DnsClientServerAddress -InterfaceAlias '{interface_alias}' -AddressFamily IPv4).ServerAddresses
Write-Output ("IP=" + $ip)
Write-Output ("GW=" + $gw)
Write-Output ("DNS=" + (($dns | ForEach-Object {{ $_ }}) -join ','))
"""
    try:
        proc = subprocess_run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        out = assess_dns_mismatch(interface_ipv4=None, gateway=None, dns_servers=[])
        out["error"] = str(exc)
        return out

    ipv4 = None
    gateway = None
    servers: list[str] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("IP="):
            ipv4 = line[3:].strip() or None
        elif line.startswith("GW="):
            gateway = line[3:].strip() or None
        elif line.startswith("DNS="):
            raw = line[4:].strip()
            servers = [p for p in raw.split(",") if p]

    result = assess_dns_mismatch(interface_ipv4=ipv4, gateway=gateway, dns_servers=servers)
    result["interface_alias"] = interface_alias
    result["collector_returncode"] = proc.returncode
    return result
