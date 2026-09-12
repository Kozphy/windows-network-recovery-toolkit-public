"""Bounded nearby loopback listener discovery (no broad port scan).

Module responsibility:
    Collect a small, scored list of loopback listeners on ports *other* than
    the target port that share a process identity, parent process, or
    command-line port reference with the primary failing listener.  Evidence
    is explicitly labelled ``"weak"`` or ``"moderate"`` to prevent
    ``LOCALHOST_PORT_CHANGED_POSSIBLE`` from being overclaimed.

System placement:
    Called by ``localhost/runner.py`` only when ``include_nearby_listeners``
    is True or fixture data is injected.  Uses a single ``netstat -ano`` call
    and does not scan arbitrary port ranges.

Key invariants:
    * Maximum *limit* results are returned (default 12) to bound data volume.
    * Every ``NearbyListener.to_dict()`` includes a hard-coded
      ``limitations`` entry: "A nearby port is not proven to be a replacement
      port without stronger evidence."
    * No new subprocess is run when ``inject`` is provided.

Side effects:
    May spawn one ``netstat -ano`` subprocess.  No filesystem writes; no
    system state changes.

Failure modes:
    Non-zero ``netstat`` exit code returns an empty list (silent soft-fail).
    Regex parse failures for individual lines are silently skipped.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .listeners import ListenerRow
from .process_info import ProcessEvidence


@dataclass(frozen=True)
class NearbyListener:
    """A loopback listener on a port adjacent to the failing target port.

    Attributes:
        local_address: Bound address of the listener.
        local_port: Port number; different from the target port.
        pid: Owner process ID, or ``None``.
        process_name: Process image name if resolved via ``tasklist``; may
            be ``None`` when PID correlation was not performed.
        relation: Relationship to the known failing listener — one of:
            ``"same_process"``, ``"same_parent_process"``,
            ``"nearby_ephemeral_port_weak"``, ``"command_line_port_reference"``.
        confidence: ``"moderate"`` for PID/parent matches; ``"weak"`` for
            ephemeral proximity.  Never ``"high"`` — nearby evidence cannot
            prove port replacement without additional corroboration.
        evidence_source: Collection method (``"netstat"`` or ``"inject"``).
    """

    local_address: str
    local_port: int
    pid: int | None
    process_name: str | None
    relation: str
    confidence: str  # weak | moderate
    evidence_source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "local_address": self.local_address,
            "local_port": self.local_port,
            "pid": self.pid,
            "process_name": self.process_name,
            "relation": self.relation,
            "confidence": self.confidence,
            "evidence_source": self.evidence_source,
            "limitations": [
                "A nearby port is not proven to be a replacement port without stronger evidence.",
            ],
        }


def _run_cmd(argv: list[str], *, run: Callable[..., Any], timeout: float) -> tuple[int, str]:
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
        return int(proc.returncode), ((proc.stdout or "") + (proc.stderr or "")).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


_ALL_LISTEN_RE = re.compile(
    r"^\s*TCP\s+(\S+):(\d+)\s+\S+\s+(LISTENING|LISTEN)\s+(\d+)\s*$",
    re.IGNORECASE,
)


def _all_loopback_listeners(text: str) -> list[ListenerRow]:
    rows: list[ListenerRow] = []
    for line in text.splitlines():
        m = _ALL_LISTEN_RE.match(line.strip())
        if not m:
            continue
        addr, port_s, state, pid_s = m.groups()
        scope_addr = addr.strip("[]")
        if scope_addr not in {
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "*",
        } and not scope_addr.startswith("127."):
            continue
        rows.append(
            ListenerRow(
                local_address=scope_addr,
                local_port=int(port_s),
                state=state.upper(),
                pid=int(pid_s),
                address_family="IPv6" if ":" in scope_addr else "IPv4",
                binding_scope="wildcard" if scope_addr in {"0.0.0.0", "::", "*"} else "loopback",
                evidence_source="netstat",
            )
        )
    return rows


def discover_nearby_listeners(
    *,
    target_port: int,
    known_listeners: list[ListenerRow],
    processes: list[ProcessEvidence],
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: list[dict[str, Any]] | None = None,
    limit: int = 12,
) -> list[NearbyListener]:
    """Return a bounded list of possibly related loopback listeners (no port scan).

    Filters all LISTENING loopback sockets from a single ``netstat -ano``
    call to those sharing process identity, parent process, or command-line
    port reference with *known_listeners* / *processes*.  Rows without a
    matching relation are excluded (not just down-scored).

    Args:
        target_port: The failing port; excluded from results.
        known_listeners: ``ListenerRow`` objects from the primary
            ``discover_listeners`` call; used to correlate by PID.
        processes: ``ProcessEvidence`` list from ``collect_process_evidence``;
            provides parent PIDs and command-line hints.
        run: Injectable ``subprocess.run`` for testing.
        timeout: Per-subprocess wall-clock timeout in seconds.
        inject: When not ``None``, bypasses live OS probes; each dict is
            converted to a ``NearbyListener`` directly.
        limit: Maximum number of results to return (default 12).

    Returns:
        Ordered list of ``NearbyListener`` objects, capped at *limit*.  An
        empty list means no related nearby listeners were found.

    Side effects:
        May spawn one ``netstat -ano`` subprocess when ``inject`` is ``None``.
    """

    if inject is not None:
        return [
            NearbyListener(
                local_address=str(r.get("local_address") or "127.0.0.1"),
                local_port=int(r["local_port"]),
                pid=int(r["pid"]) if r.get("pid") is not None else None,
                process_name=r.get("process_name"),
                relation=str(r.get("relation") or "inject"),
                confidence=str(r.get("confidence") or "weak"),
                evidence_source=str(r.get("evidence_source") or "inject"),
            )
            for r in inject[:limit]
        ]

    run_fn = run or subprocess.run
    code, out = _run_cmd(["netstat", "-ano"], run=run_fn, timeout=timeout)
    if code != 0:
        return []

    all_rows = _all_loopback_listeners(out)
    known_pids = {r.pid for r in known_listeners if r.pid is not None}
    known_names = {p.process_name for p in processes if p.process_name}
    known_parents = {p.parent_pid for p in processes if p.parent_pid is not None}
    cmd_hints = " ".join(p.command_line or "" for p in processes).lower()

    nearby: list[NearbyListener] = []
    for row in all_rows:
        if row.local_port == target_port:
            continue
        relation = None
        confidence = "weak"
        pname = None
        if row.pid in known_pids:
            relation = "same_process"
            confidence = "moderate"
        elif row.pid in known_parents:
            relation = "same_parent_process"
            confidence = "moderate"
        elif abs(row.local_port - target_port) <= 10:
            relation = "nearby_ephemeral_port_weak"
            confidence = "weak"
        if relation is None and cmd_hints and str(row.local_port) in cmd_hints:
            relation = "command_line_port_reference"
            confidence = "moderate"
        if relation is None:
            continue
        nearby.append(
            NearbyListener(
                local_address=row.local_address,
                local_port=row.local_port,
                pid=row.pid,
                process_name=pname,
                relation=relation,
                confidence=confidence,
                evidence_source=row.evidence_source,
            )
        )
        if len(nearby) >= limit:
            break

    _ = known_names  # reserved for executable/name correlation when CIM rows are enriched
    return nearby
