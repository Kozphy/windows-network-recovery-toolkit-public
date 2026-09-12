"""Read-only endpoint agent — evidence collection and JSONL spool only.

Module responsibility:
    Run observe-only collection cycles: gather endpoint evidence (live collectors or
    fixtures), append events to a local spool, emit observability metrics.

System placement:
    Invoked via ``python -m windows_network_toolkit agent *`` CLI. Does **not** call
    remediation executors listed in ``FORBIDDEN_REMEDIATION_MODULES``.

Key invariants:
    * ``READ_ONLY_POLICY_BOUNDARY`` = ``read_only_no_mutation``.
    * ``automatic_repair`` is always ``False`` on spool events.
    * Imports from ``windows_network_toolkit.safety.BLOCKED_ACTIONS`` for contract tests.

Side effects:
    Appends to spool JSONL (path from ``resolve_spool_path``); may increment in-memory
    operability counters.

Failure modes:
    Collector failures surface in evidence ``limitations``; spool write failures raise
    ``OSError`` to the CLI.

Audit Notes:
    Correlate spool ``collected_at_utc`` with ``trace_id`` / ``audit_id`` from
    ``observability_scope``. Spool files are local custody — not uploaded unless a
    separate sync path is configured.
"""

from __future__ import annotations

import json
import os
import signal
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from endpoint_agent.heartbeat import build_identity
from src.platform_core.evidence_collection import collect_endpoint_evidence
from src.platform_core.operability.context import (
    correlation_fields,
    new_audit_id,
    observability_scope,
    set_audit_id,
)
from src.platform_core.operability.events import (
    record_agent_heartbeat,
    record_evidence_collected,
    update_spool_queue_depth,
)
from windows_network_toolkit.agent.spool import (
    append_spool_event,
    read_last_spool_event,
    resolve_spool_path,
    spool_status,
)
from windows_network_toolkit.safety import BLOCKED_ACTIONS

READ_ONLY_POLICY_BOUNDARY = "read_only_no_mutation"
AGENT_VERSION = "0.2.0-read-only"

# Modules that must never be invoked from the read-only agent path (safety contract).
FORBIDDEN_REMEDIATION_MODULES = frozenset(
    {
        "windows_network_toolkit.proxy_remediation",
        "windows_network_toolkit.remediation.proxy_disable",
        "src.network_recovery.remediation_executor",
        "endpoint_agent.agent",
    }
)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def load_fixture_evidence(fixture_path: Path) -> dict[str, Any]:
    """Load evidence from a JSON fixture file into a flat evidence dict.

    If the JSON contains a top-level ``"evidence"`` key whose value is a dict,
    that nested dict is returned; otherwise the entire top-level dict is used.
    This accommodates both bare evidence dicts and wrapped fixture shapes.

    Args:
        fixture_path: Path to a JSON fixture file.

    Returns:
        Evidence dict suitable for inclusion in a spool event.

    Raises:
        FileNotFoundError: ``fixture_path`` does not exist.
        json.JSONDecodeError: File content is not valid JSON.
    """
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    if "evidence" in data and isinstance(data["evidence"], dict):
        return dict(data["evidence"])
    return dict(data)


def build_evidence_event(
    *,
    endpoint_id: str,
    os_family: str | None = None,
    fixture_path: Path | None = None,
) -> dict[str, Any]:
    """Normalise one read-only evidence collection cycle into a spool-ready event dict.

    When ``fixture_path`` is supplied the evidence is loaded from disk;
    otherwise ``collect_endpoint_evidence`` is called for live collection.
    In both cases the returned dict enforces ``read_only=True``,
    ``automatic_repair=False``, and ``remediation_executed=False``.

    Args:
        endpoint_id: Unique identifier for the endpoint being monitored.
        os_family: Optional OS family hint (e.g. ``"windows"``); inferred from
            evidence when absent.
        fixture_path: Optional path to a JSON fixture; when provided, live
            collection is skipped.

    Returns:
        A spool-ready event dict with ``event_kind``, ``endpoint_id``,
        ``collected_at_utc``, ``read_only=True``, ``automatic_repair=False``,
        ``blocked_actions``, ``evidence``, and ``limitations``.
    """
    if fixture_path is not None:
        evidence = load_fixture_evidence(fixture_path)
        effective_os = str(evidence.get("os_family") or os_family or "unknown")
    else:
        evidence = collect_endpoint_evidence(os_family)  # type: ignore[arg-type]
        effective_os = str(evidence.get("os_family") or "unknown")

    return {
        "event_kind": "agent_evidence_collected",
        "endpoint_id": endpoint_id,
        "collected_at_utc": _utc_now(),
        "agent_version": AGENT_VERSION,
        "read_only": True,
        "automatic_repair": False,
        "remediation_executed": False,
        "policy_boundary": READ_ONLY_POLICY_BOUNDARY,
        "blocked_actions": sorted(BLOCKED_ACTIONS),
        "os_family": effective_os,
        "platform_support_level": evidence.get("platform_support_level"),
        "collector_id": evidence.get("collector_id"),
        "evidence": evidence,
        "limitations": list(evidence.get("limitations") or []),
    }


def collect_once(
    *,
    spool_path: Path | None = None,
    os_family: str | None = None,
    fixture_path: Path | None = None,
    endpoint_id: str | None = None,
) -> dict[str, Any]:
    """Run one read-only collection cycle and append to the local JSONL spool.

    Side effects:
        Appends one line to the spool file only — no registry/network mutation.

    Raises:
        OSError: Spool path not writable.
    """
    path = spool_path or resolve_spool_path(None)
    ident = endpoint_id or build_identity(agent_version=AGENT_VERSION).endpoint_id
    with observability_scope() as (trace_id, _):
        aid = new_audit_id()
        set_audit_id(aid)
        event = build_evidence_event(
            endpoint_id=ident,
            os_family=os_family,
            fixture_path=fixture_path,
        )
        event.update(correlation_fields())
        event["audit_id"] = aid
        append_spool_event(path, event)
        record_evidence_collected(endpoint_id=ident, source="read_only_agent")
        record_agent_heartbeat(endpoint_id=ident, health="ok")
        status = spool_status(path)
        update_spool_queue_depth(int(status["event_count"]))
    return {
        "status": "ok",
        "endpoint_id": ident,
        "spool_path": str(path),
        "event_kind": event["event_kind"],
        "read_only": True,
        "automatic_repair": False,
        "platform_support_level": event.get("platform_support_level"),
        "observation_count": len((event.get("evidence") or {}).get("observations") or []),
        "trace_id": trace_id,
        "audit_id": aid,
    }


def _shutdown_waiter(seconds: float) -> bool:
    """Sleep up to ``seconds`` while listening for SIGINT / SIGTERM.

    Installs temporary signal handlers to allow clean shutdown; restores them
    implicitly when the event fires.  On Windows (``os.name == "nt"``) only
    ``SIGINT`` is registered, as ``SIGTERM`` is not a standard Windows signal.

    Args:
        seconds: Maximum sleep duration in seconds.

    Returns:
        ``True`` when a shutdown signal was received before the timeout;
        ``False`` when the full ``seconds`` elapsed without interruption.
    """
    stop = threading.Event()

    def _on_signal(*_args: object) -> None:
        stop.set()

    try:
        signal.signal(signal.SIGINT, _on_signal)
        if os.name != "nt":
            signal.signal(signal.SIGTERM, _on_signal)
    except ValueError:
        pass
    return stop.wait(timeout=max(0.0, seconds))


def run_agent_loop(
    *,
    interval_seconds: float = 30.0,
    spool_path: Path | None = None,
    os_family: str | None = None,
    fixture_path: Path | None = None,
    max_cycles: int | None = None,
) -> int:
    """Run read-only collection cycles until interrupted or ``max_cycles`` is reached.

    Each cycle calls ``collect_once`` then sleeps for ``interval_seconds``.
    The loop exits cleanly on SIGINT / SIGTERM or when the cycle count reaches
    ``max_cycles``.  The minimum effective interval is 5 seconds.

    Args:
        interval_seconds: Seconds to wait between collection cycles; clamped
            to a minimum of 5.0.
        spool_path: Override spool file path; see ``resolve_spool_path``.
        os_family: OS family hint forwarded to ``collect_once``.
        fixture_path: Optional fixture path forwarded to ``collect_once``.
        max_cycles: Stop after this many cycles; run indefinitely when
            ``None``.

    Returns:
        Exit code ``0`` on clean shutdown or ``max_cycles`` completion.
    """
    interval = max(5.0, float(interval_seconds))
    cycles = 0
    while True:
        collect_once(
            spool_path=spool_path,
            os_family=os_family,
            fixture_path=fixture_path,
        )
        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            return 0
        if _shutdown_waiter(interval):
            return 0


def probe_backend_health(api_base: str | None) -> dict[str, Any] | None:
    """Probe the backend ``/health`` endpoint when a base URL is configured.

    This is a best-effort read-only health check; failures are returned as a
    structured dict rather than raised.  When ``api_base`` is ``None`` or
    empty, the probe is skipped entirely.

    Args:
        api_base: Base URL of the ERP backend API (e.g.
            ``"http://127.0.0.1:8000"``).  Trailing slashes are stripped.

    Returns:
        A dict with ``api_base``, ``reachable``, ``status_code``, and ``body``
        on success; or ``api_base``, ``reachable=False``, ``error``, and
        ``detail`` on failure.  Returns ``None`` when ``api_base`` is absent.
    """
    if not api_base:
        return None
    base = api_base.rstrip("/")
    try:
        import httpx

        response = httpx.get(f"{base}/health", timeout=3.0)
        body: Any
        try:
            body = response.json()
        except json.JSONDecodeError:
            body = {"raw": response.text[:500]}
        return {
            "api_base": base,
            "reachable": True,
            "status_code": response.status_code,
            "body": body,
        }
    except Exception as exc:  # noqa: BLE001 — health probe is best-effort
        return {
            "api_base": base,
            "reachable": False,
            "error": type(exc).__name__,
            "detail": str(exc),
        }


def get_health_status(
    *,
    spool_path: Path | None = None,
    api_base: str | None = None,
) -> dict[str, Any]:
    """Return local agent health, spool status, and optional backend health probe.

    Reads the spool to determine event count and last event metadata; does not
    trigger a new collection cycle.

    Args:
        spool_path: Override spool file path; see ``resolve_spool_path``.
        api_base: Optional backend API base URL for the health probe.

    Returns:
        Dict with keys ``agent_mode="read_only"``, ``health`` (``"ok"`` or
        ``"idle"``), ``read_only=True``, ``automatic_repair=False``,
        ``remediation_executed=False``, ``policy_boundary``,
        ``blocked_actions``, ``agent_version``, ``spool``, ``last_event``,
        and ``backend`` (result of ``probe_backend_health``).
    """
    path = spool_path or resolve_spool_path(None)
    last = read_last_spool_event(path)
    status = spool_status(path)
    return {
        "agent_mode": "read_only",
        "health": "ok" if status["event_count"] > 0 else "idle",
        "read_only": True,
        "automatic_repair": False,
        "remediation_executed": False,
        "policy_boundary": READ_ONLY_POLICY_BOUNDARY,
        "blocked_actions": sorted(BLOCKED_ACTIONS),
        "agent_version": AGENT_VERSION,
        "spool": status,
        "last_event": last,
        "backend": probe_backend_health(api_base),
    }


def get_spool_status(spool_path: Path | None = None) -> dict[str, Any]:
    """Return spool depth and metadata without triggering a collection cycle.

    Args:
        spool_path: Override spool file path; see ``resolve_spool_path``.

    Returns:
        The ``spool_status`` dict from ``agent.spool.spool_status``, which
        includes ``spool_path``, ``exists``, ``event_count``,
        ``last_event_kind``, ``last_collected_at_utc``, ``last_endpoint_id``,
        and ``read_only=True``.
    """
    path = spool_path or resolve_spool_path(None)
    return spool_status(path)
