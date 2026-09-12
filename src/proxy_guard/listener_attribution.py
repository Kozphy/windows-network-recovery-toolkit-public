"""Map WinINET ``ProxyServer`` localhost ports to listening processes (medium confidence ceiling)."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from .attribution_model import AttributionEvidence, LayeredAttributionResult, ProxyActor
from .owner import attribution_payload
from .parser import parse_proxy_server
from .planning import listen_port_for_attribution

_LISTENER_NOTE = (
    "Listener attribution identifies the process listening on the configured localhost proxy port; "
    "it does not prove that process wrote the registry value."
)


def attribute_localhost_proxy_listener(
    proxy_server: str | None,
    *,
    run: Callable[..., Any] | None = None,
) -> LayeredAttributionResult:
    """Resolve localhost listening PID for parsed ``ProxyServer`` string.

    Args:
        proxy_server: Raw HKCU ``ProxyServer`` registry string (possibly multi-scheme).
        run: Optional ``subprocess.run`` surrogate for tests.

    Returns:
        :class:`~src.proxy_guard.attribution_model.LayeredAttributionResult` with ``medium`` confidence when a
        listener owner exists for the inferred port — otherwise ``unknown`` with explanatory notes only.
    """
    subprocess_run = run if run is not None else subprocess.run

    parsed = parse_proxy_server(proxy_server)
    port = listen_port_for_attribution(parsed)
    if port is None or not parsed.is_localhost_proxy:
        notes = [_LISTENER_NOTE]
        if proxy_server:
            notes.append("No localhost listen port inferred from ProxyServer string")
        return LayeredAttributionResult(
            candidate_actor=None,
            attribution_confidence="unknown",
            attribution_method="unknown",
            evidence=[
                AttributionEvidence(
                    source="localhost_listener",
                    confidence_score=0.0,
                    notes=notes,
                    raw_excerpt={"proxy_server": proxy_server},
                ),
            ],
            attribution_notes=list(dict.fromkeys(notes)),
        )

    blob = attribution_payload(int(port), run=subprocess_run)
    owners = blob.get("owners") or []
    notes_tail = list(blob.get("notes") or [])
    ev_list: list[AttributionEvidence] = [
        AttributionEvidence(
            source="localhost_listener",
            target_value_name=f"tcp_listen:{port}",
            raw_excerpt={"port": port, "listen_payload": blob},
            confidence_score=0.58,
            notes=[_LISTENER_NOTE, *(notes_tail[:3])],
        ),
    ]

    cand: ProxyActor | None = None
    first = owners[0] if owners and isinstance(owners[0], dict) else None
    if first:
        pid = first.get("pid")
        cand = ProxyActor(
            pid=int(pid) if isinstance(pid, int) else (int(pid) if isinstance(pid, str) and pid.isdigit() else None),
            process_name=str(first.get("process_name") or "").strip() or None,
            image_path=(
                str(first.get("executable_path") or "").strip() or None
                if isinstance(first.get("executable_path"), str)
                else None
            ),
            command_line=(
                str(first.get("command_line") or "").strip() or None
                if isinstance(first.get("command_line"), str)
                else None
            ),
            parent_pid=(
                int(first["parent_pid"])
                if isinstance(first.get("parent_pid"), int)
                else (
                    int(first["parent_pid"])
                    if isinstance(first.get("parent_pid"), str) and str(first["parent_pid"]).isdigit()
                    else None
                )
            ),
            parent_process_name=str(first.get("parent_name") or "").strip() or None,
        )

    return LayeredAttributionResult(
        candidate_actor=cand,
        attribution_confidence="medium" if cand and cand.pid is not None else "unknown",
        attribution_method="localhost_listener",
        evidence=ev_list,
        attribution_notes=[
            _LISTENER_NOTE,
            "Port correlation uses netstat/CIM-derived owner snapshot",
        ],
    )
