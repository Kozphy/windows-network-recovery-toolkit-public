"""Listener discovery for a localhost port (netstat + optional PowerShell).

Module responsibility:
    Enumerate TCP sockets in the LISTENING state on a target port by running
    ``netstat -ano`` and optionally ``Get-NetTCPConnection`` via PowerShell.
    Produces a ``ListenerDiscoveryResult`` that feeds the classifier and
    process-attribution steps.

System placement:
    Called by ``localhost/runner.py``.  Also used by ``nearby.py`` (via
    indirect ``netstat`` invocation) for bounded nearby-listener discovery.
    Sub-processes are spawned with ``shell=False`` and bounded timeouts.

Key invariants:
    * Fixture injection via ``inject=`` list bypasses all live OS probes for
      deterministic tests.
    * A second netstat pass detects transient listener disappearance and
      sets ``race_note`` without overclaiming a TRANSIENT_RACE classification.
    * Deduplication is done by ``(local_address, local_port, pid, source)``
      to handle overlapping results from both sources.

Side effects:
    Spawns ``netstat`` and optionally ``powershell`` subprocesses.  No files
    are written; no system state is modified.

Failure modes:
    ``netstat`` or PowerShell failures are soft-recorded in
    ``collection_errors`` and the probe continues.  A completely empty result
    (no listeners) is valid and expected when no app is listening.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class ListenerRow:
    """A single LISTENING socket row collected from netstat or Get-NetTCPConnection.

    Attributes:
        local_address: Bound address string (e.g. ``"127.0.0.1"``, ``"0.0.0.0"``);
            brackets stripped for IPv6 literals.
        local_port: The listening TCP port number.
        state: Socket state string (always ``"LISTENING"`` from these sources).
        pid: Owner process ID, or ``None`` when access is denied.
        address_family: ``"IPv4"`` or ``"IPv6"`` inferred from *local_address*.
        binding_scope: ``"loopback"`` | ``"wildcard"`` | ``"other"`` — used by
            the classifier to detect IPv4/IPv6 bind-mismatch patterns.
        evidence_source: Collection method (``"netstat"`` or
            ``"Get-NetTCPConnection"``).
    """

    local_address: str
    local_port: int
    state: str
    pid: int | None
    address_family: str
    binding_scope: str  # loopback | wildcard | other
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
            "state": self.state,
            "pid": self.pid,
            "address_family": self.address_family,
            "binding_scope": self.binding_scope,
            "evidence_source": self.evidence_source,
        }


@dataclass
class ListenerDiscoveryResult:
    """Aggregated listener discovery outcome for a single port.

    Attributes:
        port: The target port that was probed.
        listeners: Deduplicated list of ``ListenerRow`` objects found.
        sources_tried: Ordered list of collection methods attempted
            (``"netstat"``, ``"Get-NetTCPConnection"``, ``"inject"``).
        collection_errors: Non-fatal errors from each source (e.g. process
            timeout, access denied); empty on clean runs.
        timestamp_utc: ISO-8601 UTC timestamp at probe start.
        race_note: Set to a human-readable warning string when the second
            pass detects listener disappearance or PID churn between the two
            netstat passes.  ``None`` when no race is detected.
    """

    port: int
    listeners: list[ListenerRow] = field(default_factory=list)
    sources_tried: list[str] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)
    timestamp_utc: str = ""
    race_note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "port": self.port,
            "listeners": [x.to_dict() for x in self.listeners],
            "sources_tried": list(self.sources_tried),
            "collection_errors": list(self.collection_errors),
            "timestamp_utc": self.timestamp_utc,
            "race_note": self.race_note,
        }


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_cmd(argv: list[str], *, run: Callable[..., Any], timeout: float) -> tuple[int, str]:
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
        return int(proc.returncode), ((proc.stdout or "") + (proc.stderr or "")).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _binding_scope(addr: str) -> str:
    a = addr.lower().strip("[]")
    if a in {"0.0.0.0", "*", "::", "::0"}:
        return "wildcard"
    if a in {"127.0.0.1", "::1", "localhost"} or a.startswith("127."):
        return "loopback"
    return "other"


def _family(addr: str) -> str:
    a = addr.strip("[]")
    return "IPv6" if ":" in a else "IPv4"


_NETSTAT_RE = re.compile(
    r"^\s*(TCP)\s+(\S+):(\d+)\s+\S+\s+(LISTENING|LISTEN)\s+(\d+)\s*$",
    re.IGNORECASE,
)


def parse_netstat_listening(text: str, port: int) -> list[ListenerRow]:
    """Parse ``netstat -ano`` output for LISTENING rows on *port*."""

    rows: list[ListenerRow] = []
    for line in text.splitlines():
        m = _NETSTAT_RE.match(line.strip())
        if not m:
            # Broader fallback for localized spacing / IPv6 brackets
            upper = line.upper()
            if "LISTENING" not in upper and " LISTEN" not in upper:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[1]
            if ":" not in local:
                continue
            # IPv6 like [::]:61161 or 0.0.0.0:61161
            host_part, _, port_part = local.rpartition(":")
            try:
                p = int(port_part)
            except ValueError:
                continue
            if p != port:
                continue
            try:
                pid = int(parts[-1])
            except ValueError:
                pid = None
            rows.append(
                ListenerRow(
                    local_address=host_part.strip("[]") or host_part,
                    local_port=p,
                    state="LISTENING",
                    pid=pid,
                    address_family=_family(host_part),
                    binding_scope=_binding_scope(host_part),
                    evidence_source="netstat",
                )
            )
            continue
        _proto, addr, port_s, state, pid_s = m.groups()
        if int(port_s) != port:
            continue
        rows.append(
            ListenerRow(
                local_address=addr.strip("[]"),
                local_port=int(port_s),
                state=state.upper(),
                pid=int(pid_s),
                address_family=_family(addr),
                binding_scope=_binding_scope(addr),
                evidence_source="netstat",
            )
        )
    return rows


def _discover_via_netstat(
    port: int, *, run: Callable[..., Any], timeout: float
) -> tuple[list[ListenerRow], str | None]:
    code, out = _run_cmd(["netstat", "-ano"], run=run, timeout=timeout)
    if code != 0:
        return [], f"netstat failed: {out[:300]}"
    return parse_netstat_listening(out, port), None


def _discover_via_powershell(
    port: int, *, run: Callable[..., Any], timeout: float
) -> tuple[list[ListenerRow], str | None]:
    # Argument array — no shell concatenation of untrusted input beyond int port.
    ps = (
        f"Get-NetTCPConnection -LocalPort {int(port)} -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,OwningProcess,State | ConvertTo-Csv -NoTypeInformation"
    )
    code, out = _run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        run=run,
        timeout=timeout,
    )
    if code != 0 or not out.strip():
        return [], None if code == 0 else f"Get-NetTCPConnection failed: {out[:300]}"
    rows: list[ListenerRow] = []
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        return [], None
    for line in lines[1:]:
        # CSV: "LocalAddress","LocalPort","OwningProcess","State"
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) < 4:
            continue
        addr, port_s, pid_s, state = parts[0], parts[1], parts[2], parts[3]
        try:
            p = int(port_s)
            pid = int(pid_s) if pid_s else None
        except ValueError:
            continue
        if p != port:
            continue
        rows.append(
            ListenerRow(
                local_address=addr.strip("[]"),
                local_port=p,
                state=str(state).upper() or "LISTEN",
                pid=pid,
                address_family=_family(addr),
                binding_scope=_binding_scope(addr),
                evidence_source="Get-NetTCPConnection",
            )
        )
    return rows, None


def discover_listeners(
    port: int,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: list[dict[str, Any]] | None = None,
    second_pass: bool = True,
) -> ListenerDiscoveryResult:
    """Discover LISTENING sockets on *port* with graceful fallbacks.

    Attempts ``netstat -ano`` first; falls back to ``Get-NetTCPConnection``
    via PowerShell when netstat returns no rows.  Optionally runs a second
    netstat pass to detect transient listener churn.

    Args:
        port: TCP port to search for LISTENING rows.
        run: Injectable ``subprocess.run`` replacement for testing.
        timeout: Per-subprocess wall-clock timeout in seconds.
        inject: When not ``None``, bypasses all live OS probes and builds
            ``ListenerRow`` objects from the provided dicts.  Used for
            deterministic unit tests.
        second_pass: When ``True`` and live listeners were found, a second
            netstat pass checks for transient disappearance and sets
            ``race_note`` if PID sets differ.

    Returns:
        ``ListenerDiscoveryResult`` with discovered listeners and any
        soft errors.  Never raises; errors are recorded in
        ``collection_errors``.

    Side effects:
        Spawns ``netstat`` and possibly ``powershell`` child processes.
        No filesystem writes; no system state changes.
    """

    result = ListenerDiscoveryResult(port=port, timestamp_utc=_now())
    if inject is not None:
        result.sources_tried.append("inject")
        for row in inject:
            result.listeners.append(
                ListenerRow(
                    local_address=str(row.get("local_address") or "127.0.0.1"),
                    local_port=int(row.get("local_port") or port),
                    state=str(row.get("state") or "LISTENING"),
                    pid=int(row["pid"]) if row.get("pid") is not None else None,
                    address_family=str(row.get("address_family") or "IPv4"),
                    binding_scope=str(
                        row.get("binding_scope")
                        or _binding_scope(str(row.get("local_address") or ""))
                    ),
                    evidence_source=str(row.get("evidence_source") or "inject"),
                )
            )
        return result

    run_fn = run or subprocess.run
    result.sources_tried.append("netstat")
    rows, err = _discover_via_netstat(port, run=run_fn, timeout=timeout)
    if err:
        result.collection_errors.append(err)
    result.listeners.extend(rows)

    if not result.listeners:
        result.sources_tried.append("Get-NetTCPConnection")
        ps_rows, ps_err = _discover_via_powershell(port, run=run_fn, timeout=timeout)
        if ps_err:
            result.collection_errors.append(ps_err)
        result.listeners.extend(ps_rows)

    if second_pass and result.listeners:
        # Detect transient disappearance without overclaiming.
        again, _ = _discover_via_netstat(port, run=run_fn, timeout=timeout)
        first_pids = {r.pid for r in result.listeners if r.pid is not None}
        second_pids = {r.pid for r in again if r.pid is not None}
        if first_pids and not second_pids:
            result.race_note = (
                "Listener present on first pass but absent on second — possible transient race."
            )
        elif first_pids != second_pids and second_pids:
            result.race_note = (
                "Listener PID set changed between collection passes — avoid overconfidence."
            )

    # Deduplicate by (address, port, pid, source)
    seen: set[tuple[Any, ...]] = set()
    unique: list[ListenerRow] = []
    for row in result.listeners:
        key = (row.local_address, row.local_port, row.pid, row.evidence_source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    result.listeners = unique
    return result
