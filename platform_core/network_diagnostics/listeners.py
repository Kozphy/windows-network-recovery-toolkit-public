"""Read-only listening-port evidence for POSIX hosts (Linux/macOS).

Candidate evidence only — not process attribution or registry-writer proof.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any

from platform_core.network_diagnostics.base import observation

_COMMON_PROXY_PORTS = (8080, 3128, 8888, 1080, 9050, 7890)


def _run_text(cmd: list[str], *, timeout: float = 6.0) -> tuple[int, str]:
    if shutil.which(cmd[0]) is None:
        return 127, ""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def _parse_ss_or_netstat(text: str) -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if lower.startswith("state") or lower.startswith("active"):
            continue
        upper = stripped.upper()
        if "LISTEN" not in upper:
            continue
        if upper.startswith("LISTEN"):
            parts = stripped.split()
            if len(parts) >= 4 and ":" in parts[3]:
                host, _, port_s = parts[3].rpartition(":")
                try:
                    listeners.append({"address": host, "port": int(port_s)})
                except ValueError:
                    pass
            continue
        parts = stripped.split()
        if not parts or parts[-1].upper() != "LISTEN" or len(parts) < 4:
            continue
        local = parts[3]
        if "." in local and ":" not in local:
            match = re.match(r"^(.+)\.(\d+)$", local)
            if match:
                listeners.append({"address": match.group(1), "port": int(match.group(2))})
                continue
        if ":" in local:
            host, _, port_s = local.rpartition(":")
            try:
                listeners.append({"address": host, "port": int(port_s)})
            except ValueError:
                pass
    return listeners


def probe_listening_ports() -> dict[str, Any]:
    """Summarize TCP listeners via ``ss`` or ``netstat`` when safely available."""
    source = "none"
    output = ""
    code = 1
    if shutil.which("ss"):
        code, output = _run_text(["ss", "-tln"])
        source = "ss"
    elif shutil.which("netstat"):
        code, output = _run_text(["netstat", "-an"])
        source = "netstat"

    if code != 0 or not output.strip():
        return {
            "available": False,
            "source": source,
            "listener_count": 0,
            "localhost_listener_count": 0,
            "common_proxy_ports": [],
            "error": "listener_probe_unavailable" if source == "none" else "listener_probe_failed",
        }

    listeners = _parse_ss_or_netstat(output)
    localhost = [
        row
        for row in listeners
        if row["address"] in ("127.0.0.1", "::1", "localhost", "*", "0.0.0.0", "::")
    ]
    common_hits = sorted(
        {row["port"] for row in listeners if row["port"] in _COMMON_PROXY_PORTS}
    )
    return {
        "available": True,
        "source": source,
        "listener_count": len(listeners),
        "localhost_listener_count": len(localhost),
        "common_proxy_ports": common_hits,
    }


def listening_port_observations(*, source: str) -> list[dict[str, Any]]:
    """Return normalized listening-port observations with explicit limitations."""
    probe = probe_listening_ports()
    lim = [
        "listener_summary_is_candidate_evidence_not_proof",
        "no_process_attribution_on_linux_macos_foundation_path",
    ]
    rows: list[dict[str, Any]] = [
        observation(
            "listening_port_probe_available",
            probe.get("available", False),
            source=source,
            limitations=lim,
        )
    ]
    if probe.get("available"):
        rows.extend(
            [
                observation(
                    "listening_port_count",
                    probe.get("listener_count", 0),
                    source=source,
                    detail={"tool": probe.get("source")},
                    limitations=lim,
                ),
                observation(
                    "localhost_listener_count",
                    probe.get("localhost_listener_count", 0),
                    source=source,
                    limitations=lim,
                ),
                observation(
                    "common_proxy_ports_listening",
                    ",".join(str(p) for p in probe.get("common_proxy_ports") or []) or "none",
                    source=source,
                    limitations=lim,
                ),
            ]
        )
    else:
        rows.append(
            observation(
                "listening_port_probe_error",
                str(probe.get("error") or "unavailable"),
                source=source,
                limitations=lim + ["ss_and_netstat_unavailable_or_failed"],
            )
        )
    return rows
