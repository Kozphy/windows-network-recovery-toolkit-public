"""WinINET/WinHTTP proxy evidence for localhost diagnose (read-only).

Module responsibility:
    Collect the current WinINET proxy registry settings and WinHTTP direct-
    access state, then relate them cautiously to the localhost connection
    failure under investigation.  The result feeds the classifier and the
    proxy-interference branch of the diagnose report.

System placement:
    Called by ``localhost/runner.py`` unconditionally; the result is always
    present in the report even when proxy state is not the primary finding.
    Relies on ``windows_network_toolkit.collectors.proxy_registry_collector``
    for registry reads and ``netsh winhttp show proxy`` for WinHTTP state.

Key invariants:
    * ``points_to_dead_local_proxy`` is True only when all three conditions
      hold: WinINET proxy enabled, proxy server resolves to localhost, and
      the target port matches the proxy port with no TCP success.
    * ``relation_to_incident`` is ``"possible_proxy_interference"`` only when
      both direct HTTP succeeds AND proxy-aware HTTP fails AND WinINET is
      enabled.  Ambiguous or both-failing paths are never labelled
      ``possible_proxy_interference``.
    * Every ``ProxyEvidence`` instance carries a hard-coded ``limitations``
      list that prevents proxy-disable recommendations based on this data alone.

Side effects:
    Reads Windows registry via ``collect_proxy_registry`` and spawns
    ``netsh winhttp show proxy``.  No writes; no system state changes.

Failure modes:
    ``netsh`` subprocess timeout or ``OSError`` sets ``winhttp_raw_excerpt``
    to the exception string and ``winhttp_direct`` to ``None``.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from windows_network_toolkit.collectors.proxy_registry_collector import collect_proxy_registry


@dataclass
class ProxyEvidence:
    """Snapshot of WinINET and WinHTTP proxy state related to a localhost incident.

    Attributes:
        wininet_enabled: ``True`` when ``HKCU\\…\\Internet Settings\\ProxyEnable`` is 1.
        wininet_proxy_server: Raw ``ProxyServer`` registry value, or ``None``.
        wininet_proxy_override: Raw ``ProxyOverride`` registry value; used to
            detect ``<local>`` / ``localhost`` bypass tokens.
        localhost_bypass_likely: ``True`` when the proxy override list contains
            a loopback bypass token.  ``None`` when ``ProxyOverride`` is absent.
        winhttp_direct: ``True`` when ``netsh winhttp show proxy`` output
            indicates "Direct access" and "No proxy server".  ``None`` on error.
        winhttp_raw_excerpt: First 400 chars of ``netsh`` output (or error).
        points_to_dead_local_proxy: ``True`` only when WinINET is enabled, the
            proxy server resolves to localhost, and TCP to the proxy port failed.
        relation_to_incident: Ordinal relationship label — one of:
            ``"possible_proxy_interference"``, ``"unrelated_or_both_paths_failed"``,
            ``"proxy_unrelated_to_incident"``, ``"inconclusive"``, ``"unknown"``.
        limitations: Hard-coded caveats included in every serialization to
            prevent downstream overconfidence.
        timestamp_utc: ISO-8601 UTC timestamp at collection start.
    """

    wininet_enabled: bool | None = None
    wininet_proxy_server: str | None = None
    wininet_proxy_override: str | None = None
    localhost_bypass_likely: bool | None = None
    winhttp_direct: bool | None = None
    winhttp_raw_excerpt: str | None = None
    points_to_dead_local_proxy: bool | None = None
    relation_to_incident: str = "unknown"
    limitations: list[str] = field(default_factory=list)
    timestamp_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "wininet_enabled": self.wininet_enabled,
            "wininet_proxy_server": self.wininet_proxy_server,
            "wininet_proxy_override": self.wininet_proxy_override,
            "localhost_bypass_likely": self.localhost_bypass_likely,
            "winhttp_direct": self.winhttp_direct,
            "winhttp_raw_excerpt": self.winhttp_raw_excerpt,
            "points_to_dead_local_proxy": self.points_to_dead_local_proxy,
            "relation_to_incident": self.relation_to_incident,
            "limitations": list(self.limitations),
            "timestamp_utc": self.timestamp_utc,
        }


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bypass_localhost(override: str | None) -> bool | None:
    if override is None:
        return None
    o = override.lower()
    # Common bypass tokens for loopback
    return any(tok in o for tok in ("<local>", "localhost", "127.0.0.1", "<-loopback>"))


def collect_proxy_evidence(
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: dict[str, Any] | None = None,
    target_port: int | None = None,
    tcp_any_success: bool = False,
    http_direct_ok: bool | None = None,
    http_proxy_ok: bool | None = None,
) -> ProxyEvidence:
    """Collect proxy state and relate it cautiously to the localhost incident.

    Reads WinINET registry and WinHTTP state, then derives
    ``points_to_dead_local_proxy`` and ``relation_to_incident`` based on
    the cross-signal combination of TCP success, HTTP probe outcomes, and
    proxy configuration.

    Args:
        run: Injectable ``subprocess.run`` for testing.
        timeout: Per-subprocess wall-clock timeout in seconds.
        inject: When not ``None``, populates a ``ProxyEvidence`` from the dict
            directly (fixture mode; no subprocesses are spawned).
        target_port: Port being diagnosed; used to match against the WinINET
            proxy server port when computing ``points_to_dead_local_proxy``.
        tcp_any_success: ``True`` when at least one TCP probe to *target_port*
            succeeded; suppresses dead-local-proxy detection.
        http_direct_ok: ``True`` / ``False`` from the direct HTTP probe result;
            ``None`` when no HTTP probes were run.
        http_proxy_ok: ``True`` / ``False`` from the proxy-aware probe result;
            ``None`` when not run.

    Returns:
        A ``ProxyEvidence`` dataclass; always includes ``limitations[]``.

    Side effects:
        Reads registry via ``collect_proxy_registry``; spawns
        ``netsh winhttp show proxy``.  No writes; no state changes.

    Audit note:
        ``relation_to_incident`` feeds the ``LOCALHOST_PROXY_INTERFERENCE``
        classification branch.  Only ``"possible_proxy_interference"`` enables
        that branch, so this function is on the critical path for any
        proxy-related remediation suggestion.
    """

    ev = ProxyEvidence(
        timestamp_utc=_now(),
        limitations=[
            "A localhost page failure does not by itself justify proxy-disable.",
            "Proxy evidence is observational; dead-proxy claims require listener/TCP corroboration.",
        ],
    )
    if inject is not None:
        for k, v in inject.items():
            if hasattr(ev, k):
                setattr(ev, k, v)
        return ev

    run_fn = run or subprocess.run
    snap = collect_proxy_registry(run=run_fn)
    enable = snap.get("proxy_enable")
    ev.wininet_enabled = int(enable or 0) == 1 if enable is not None else None
    ev.wininet_proxy_server = snap.get("proxy_server")
    ev.wininet_proxy_override = snap.get("proxy_override")
    ev.localhost_bypass_likely = _bypass_localhost(ev.wininet_proxy_override)

    try:
        proc = run_fn(
            ["netsh", "winhttp", "show", "proxy"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
        raw = ((proc.stdout or "") + (proc.stderr or "")).strip()
        lower = raw.lower()
        ev.winhttp_raw_excerpt = raw[:400]
        ev.winhttp_direct = "direct access" in lower and "no proxy server" in lower
    except (OSError, subprocess.TimeoutExpired) as exc:
        ev.winhttp_raw_excerpt = str(exc)[:200]
        ev.winhttp_direct = None

    server = str(ev.wininet_proxy_server or "")
    local_proxy = bool(re.search(r"127(?:\.\d{1,3}){3}|localhost", server, re.I))
    proxy_port = None
    pm = re.search(r":(\d{1,5})", server)
    if pm:
        proxy_port = int(pm.group(1))

    # Dead local proxy: enabled + localhost proxy + TCP to that proxy port failed elsewhere —
    # here we only flag when target_port equals proxy port and TCP failed.
    if ev.wininet_enabled and local_proxy and proxy_port is not None:
        if target_port == proxy_port and not tcp_any_success:
            ev.points_to_dead_local_proxy = True
        else:
            ev.points_to_dead_local_proxy = False
    else:
        ev.points_to_dead_local_proxy = False

    if http_direct_ok is True and http_proxy_ok is False and ev.wininet_enabled:
        ev.relation_to_incident = "possible_proxy_interference"
    elif http_direct_ok is False and http_proxy_ok is False:
        ev.relation_to_incident = "unrelated_or_both_paths_failed"
    elif not ev.wininet_enabled and (ev.winhttp_direct is True or ev.winhttp_direct is None):
        ev.relation_to_incident = "proxy_unrelated_to_incident"
    elif tcp_any_success is False and not (
        ev.wininet_enabled and local_proxy and target_port == proxy_port
    ):
        ev.relation_to_incident = "proxy_unrelated_to_incident"
    else:
        ev.relation_to_incident = "inconclusive"

    return ev
