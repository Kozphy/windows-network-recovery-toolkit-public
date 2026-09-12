"""Read-only validation probes for investigation runs.

Module responsibility:
    Run DNS/TCP/HTTPS connectivity checks and optional proxy-path contrast assessment
    to distinguish loopback proxy health from generic outage.

System placement:
    Invoked by ``workflow`` after collectors; feeds ``hypotheses`` ranking.

Input assumptions:
    Live WinINET registry readable on Windows; ``capture_connectivity_snapshot`` receives
    the current proxy snapshot from registry reads in this module.

Output guarantees:
    Tuple of (validation dict, path_assessment dict or None) with boolean probe flags.

Side effects:
    Network probes and subprocess execution; no configuration mutations.

Failure modes:
    Probe failures surface as ``*_ok`` false flags; does not raise solely on probe miss.

Audit Notes:
    * Probe success does not prove benign intent — only reachability.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from ..proxy_guard.connectivity import capture_connectivity_snapshot
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.proxy_path_operational import assess_proxy_path_operational
from ..proxy_guard.registry import read_proxy_registry


def run_validation(
    *,
    run: Callable[..., Any] = subprocess.run,
    timeout_seconds: float = 15.0,
    include_https_contrast: bool = True,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Run DNS, TCP 443, HTTPS, and optional proxy-path contrast probes.

    Args:
        run: Injectable subprocess runner for tests.
        timeout_seconds: Per-probe timeout budget.
        include_https_contrast: When True, include bypass vs proxied HTTPS contrast in path assessment.

    Returns:
        Tuple of validation summary dict and serialized path assessment (or None).

    Side effects:
        Outbound network checks via ``proxy_guard.connectivity`` and path assessment helpers.
    """
    reg = read_proxy_registry(run=run, query_timeout=timeout_seconds)
    parsed = parse_proxy_server(reg.proxy_server)
    conn = capture_connectivity_snapshot(
        run=run,
        snapshot=reg,
        timeout_seconds=timeout_seconds,
    )
    path = assess_proxy_path_operational(
        proxy_enable=reg.proxy_enable,
        proxy_server=reg.proxy_server,
        auto_config_url=reg.auto_config_url,
        parsed=parsed,
        port_listen=None,
        run=run,
        include_https_contrast=include_https_contrast,
        timeout_seconds=timeout_seconds,
    )
    operational = path.operational
    validation = {
        "dns_ok": conn.dns_google.ok,
        "tcp_443_ok": conn.tcp_443_google.ok,
        "https_ok": conn.https_google.ok,
        "https_microsoft_ok": conn.https_microsoft.ok,
        "proxy_bypass_https_ok": operational.get("bypass_https_ok"),
        "proxied_https_ok": operational.get("proxied_https_ok"),
        "connectivity_snapshot": conn.to_jsonable(),
        "limitations": [
            "Probes validate reachability only; they do not prove registry writer identity.",
        ],
    }
    return validation, path.to_jsonable()
