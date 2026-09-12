"""Passive localhost proxy listener inspection (prefer psutil; no outbound connect).

Module responsibility:
    Observe whether a TCP listener is bound on a localhost proxy port and, when
    permitted, resolve the owning PID/process name — without opening outbound sockets.

System placement:
    Called by ``ProxyWatcher`` when ``DashboardProxyState`` indicates a localhost proxy.

Key invariants:
    * Prefer ``psutil.net_connections``; injectables enable fixture tests.
    * Access-denied and process-exited are soft-fail flags, not hard errors.
    * Listener presence correlates with ProxyServer; it does not prove who wrote HKCU.

Side effects:
    * Read-only OS process/connection table queries (when not using ``inject``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class LocalProxyListener:
    """Immutable listener observation for one localhost port check.

    Attributes:
        listener_present: True when a loopback LISTEN socket matches the port.
        listener_pid: Owning PID when resolvable.
        listener_process_name: Process image name when resolvable.
        listener_address: Bound address string when known.
        listener_port: Port checked / observed.
        access_denied: True when OS denied connection table or process lookup.
        process_exited: True when PID vanished during name resolution.
        evidence_source: ``psutil``, ``inject``, or other collector tag.
        errors: Soft-fail messages for audit/UI.
        timestamp_utc: UTC ``Z`` timestamp of the check.
    """

    listener_present: bool
    listener_pid: int | None
    listener_process_name: str | None
    listener_address: str | None
    listener_port: int | None
    access_denied: bool = False
    process_exited: bool = False
    evidence_source: str = "psutil"
    errors: tuple[str, ...] = ()
    timestamp_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise the listener observation to a plain dict safe for JSON output."""
        return {
            "listener_present": self.listener_present,
            "listener_pid": self.listener_pid,
            "listener_process_name": self.listener_process_name,
            "listener_address": self.listener_address,
            "listener_port": self.listener_port,
            "access_denied": self.access_denied,
            "process_exited": self.process_exited,
            "evidence_source": self.evidence_source,
            "errors": list(self.errors),
            "timestamp_utc": self.timestamp_utc,
        }


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_loopback_ip(addr: str | None) -> bool:
    """Return ``True`` when ``addr`` resolves to a loopback or wildcard address.

    Recognised addresses: ``127.x.x.x``, ``::1``, ``0.0.0.0``, ``::``, ``*``.
    """
    if not addr:
        return False
    a = addr.strip("[]").lower()
    return a in {"127.0.0.1", "::1", "0.0.0.0", "::", "*"} or a.startswith("127.")


def check_local_proxy_listener(
    port: int | None,
    *,
    inject: dict[str, Any] | None = None,
    connections_fn: Callable[[], list[Any]] | None = None,
    process_name_fn: Callable[[int], str | None] | None = None,
) -> LocalProxyListener:
    """Return listener evidence for *port* using passive connection tables.

    Args:
        port: Localhost proxy port from ProxyServer, or None (returns absent listener).
        inject: Optional fixture dict skipping live OS queries.
        connections_fn: Optional override returning connection objects (tests).
        process_name_fn: Optional override mapping PID → name (tests).

    Returns:
        ``LocalProxyListener`` snapshot. Never raises for access denied; sets flags.

    Side effects:
        May call ``psutil`` when inject/overrides are absent.
    """

    ts = _now()
    if inject is not None:
        return LocalProxyListener(
            listener_present=bool(inject.get("listener_present")),
            listener_pid=inject.get("listener_pid"),
            listener_process_name=inject.get("listener_process_name"),
            listener_address=inject.get("listener_address"),
            listener_port=int(inject["listener_port"])
            if inject.get("listener_port") is not None
            else port,
            access_denied=bool(inject.get("access_denied")),
            process_exited=bool(inject.get("process_exited")),
            evidence_source=str(inject.get("evidence_source") or "inject"),
            errors=tuple(inject.get("errors") or ()),
            timestamp_utc=str(inject.get("timestamp_utc") or ts),
        )

    if port is None:
        return LocalProxyListener(
            listener_present=False,
            listener_pid=None,
            listener_process_name=None,
            listener_address=None,
            listener_port=None,
            evidence_source="none",
            timestamp_utc=ts,
        )

    errors: list[str] = []
    access_denied = False
    conns: list[Any]
    if connections_fn is not None:
        try:
            conns = list(connections_fn())
        except PermissionError as exc:
            return LocalProxyListener(
                listener_present=False,
                listener_pid=None,
                listener_process_name=None,
                listener_address=None,
                listener_port=port,
                access_denied=True,
                evidence_source="injectable",
                errors=(str(exc),),
                timestamp_utc=ts,
            )
    else:
        try:
            import psutil

            try:
                conns = list(psutil.net_connections(kind="tcp"))
            except (psutil.AccessDenied, PermissionError) as exc:
                access_denied = True
                errors.append(str(exc))
                conns = []
        except ImportError:
            # Fallback: existing netstat-based resolver
            return _fallback_netstat(port, ts)

    for c in conns:
        try:
            status = getattr(c, "status", None) or (
                c.get("status") if isinstance(c, dict) else None
            )
            laddr = getattr(c, "laddr", None) or (c.get("laddr") if isinstance(c, dict) else None)
            pid = getattr(c, "pid", None) if not isinstance(c, dict) else c.get("pid")
            if str(status).upper() not in {"LISTEN", "LISTENING"}:
                continue
            if laddr is None:
                continue
            if hasattr(laddr, "port"):
                lip, lport = str(laddr.ip), int(laddr.port)
            elif isinstance(laddr, tuple | list) and len(laddr) >= 2:
                lip, lport = str(laddr[0]), int(laddr[1])
            elif isinstance(laddr, dict):
                lip, lport = str(laddr.get("ip")), int(laddr.get("port"))
            else:
                continue
            if lport != int(port):
                continue
            if not _is_loopback_ip(lip) and lip not in {"0.0.0.0", "::"}:
                continue
            name = None
            process_exited = False
            if pid:
                if process_name_fn is not None:
                    name = process_name_fn(int(pid))
                else:
                    try:
                        import psutil

                        name = psutil.Process(int(pid)).name()
                    except Exception as exc:  # noqa: BLE001
                        if "NoSuchProcess" in type(exc).__name__ or "not found" in str(exc).lower():
                            process_exited = True
                        elif "AccessDenied" in type(exc).__name__ or "denied" in str(exc).lower():
                            access_denied = True
                        errors.append(str(exc)[:200])
            return LocalProxyListener(
                listener_present=True,
                listener_pid=int(pid) if pid else None,
                listener_process_name=name,
                listener_address=lip,
                listener_port=lport,
                access_denied=access_denied,
                process_exited=process_exited,
                evidence_source="psutil" if connections_fn is None else "injectable",
                errors=tuple(errors),
                timestamp_utc=ts,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc)[:200])
            continue

    return LocalProxyListener(
        listener_present=False,
        listener_pid=None,
        listener_process_name=None,
        listener_address=None,
        listener_port=port,
        access_denied=access_denied,
        evidence_source="psutil" if connections_fn is None else "injectable",
        errors=tuple(errors),
        timestamp_utc=ts,
    )


def _fallback_netstat(port: int, ts: str) -> LocalProxyListener:
    """Resolve listener ownership via the platform attribution collector.

    Used when ``psutil`` is not importable.  Delegates to
    ``src.platform_core.attribution.collector.resolve_listener_process`` via
    ``subprocess.run``.  Soft-fails on any exception — returns an absent
    listener with the error string recorded.

    Args:
        port: TCP port to check.
        ts: Pre-computed UTC timestamp string for the returned snapshot.

    Returns:
        ``LocalProxyListener`` with ``evidence_source`` ``"netstat_fallback"``.
    """

    try:
        import subprocess

        from src.platform_core.attribution.collector import resolve_listener_process

        attr, found = resolve_listener_process(port, run=subprocess.run, timeout=15.0)
        return LocalProxyListener(
            listener_present=bool(found),
            listener_pid=getattr(attr, "pid", None),
            listener_process_name=getattr(attr, "process_name", None)
            or getattr(attr, "name", None),
            listener_address="127.0.0.1",
            listener_port=port,
            evidence_source="netstat_fallback",
            timestamp_utc=ts,
        )
    except Exception as exc:  # noqa: BLE001
        return LocalProxyListener(
            listener_present=False,
            listener_pid=None,
            listener_process_name=None,
            listener_address=None,
            listener_port=port,
            evidence_source="netstat_fallback",
            errors=(str(exc),),
            timestamp_utc=ts,
        )
