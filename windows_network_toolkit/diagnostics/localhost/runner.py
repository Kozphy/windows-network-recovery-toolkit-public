"""Orchestrate localhost-diagnose: observe → classify → policy preview → audit.

Module responsibility:
    Coordinate all localhost diagnostic sub-steps — target parsing, name
    resolution, TCP probing, listener discovery, process attribution, HTTP
    comparison, proxy-evidence collection, nearby-listener discovery,
    classification, and remediation preview — into a single audit-ready
    report dict.  Also provides ``render_localhost_diagnose`` for CLI output.

System placement:
    Entry point for ``python -m windows_network_toolkit localhost-diagnose``.
    Imported and re-exported by ``localhost/__init__.py``.  Uses fixture
    injection (``inject=…``) as the primary test seam to avoid live OS probes
    in unit tests.

Key invariants:
    * The runner is unconditionally read-only; it never mutates proxy,
      firewall, registry, or service state.
    * ``attach_governance_envelope`` is always applied before return.
    * Audit JSONL is soft-appended via ``append_audit_dict``; a write failure
      is recorded in ``report["warnings"]`` and does not abort the run.
    * HTTP probes are skipped entirely when no TCP probe succeeded, to avoid
      confusing partial HTTP errors with TCP failures.

Side effects:
    Soft-appends to ``.audit/localhost-diagnose.jsonl``.
    Writes ``evidence_out`` file when the parameter is provided.
    Spawns subprocesses for netstat, powershell, and tasklist.

Failure modes:
    ``TargetValidationError`` triggers an early-exit report with T0
    classification before any probes run.  Per-step subprocess failures are
    accumulated in ``collection_errors``; the run completes with lower
    confidence rather than aborting.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from windows_network_toolkit import __version__
from windows_network_toolkit.audit_store import append_audit_dict

from .classifier import classify_localhost_failure
from .formatters import format_localhost_diagnose_human
from .http_probe import compare_http_probes, http_probe_direct, http_probe_proxy_aware
from .listeners import discover_listeners
from .nearby import discover_nearby_listeners
from .process_info import collect_process_evidence
from .proxy_evidence import collect_proxy_evidence
from .remediation import build_remediation_preview, policy_envelope
from .resolution import loopback_probe_addresses, resolve_localhost_host
from .target import LocalhostTarget, TargetValidationError, parse_localhost_target
from .tcp_probe import tcp_probe_many


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_localhost_diagnose(
    *,
    url: str | None = None,
    host: str | None = None,
    port: int | None = None,
    path: str | None = None,
    timeout: float = 2.0,
    include_process: bool = False,
    include_http: bool = False,
    include_proxy_comparison: bool = False,
    include_nearby_listeners: bool = False,
    remediation_preview: bool = False,
    evidence_out: str | Path | None = None,
    allow_non_loopback: bool = False,
    run: Callable[..., Any] | None = None,
    inject: dict[str, Any] | None = None,
    prior_listener_evidence: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """Run read-only localhost web-app diagnosis and return an audit-ready report.

    Args:
        inject: Optional deterministic fixture dict with keys such as ``resolution``,
            ``tcp_probes``, ``listeners``, ``processes``, ``http_probes``, ``proxy_evidence``,
            ``nearby_listeners``.

    Side effects:
        Soft-appends ``.audit/localhost-diagnose.jsonl``; may write ``evidence_out``.
        Never mutates proxy, firewall, registry, or services.
    """

    errors: list[dict[str, str]] = []
    warnings: list[str] = []
    event_id = f"lh-{uuid.uuid4().hex[:12]}"
    correlation_id = event_id
    inj = inject or {}

    try:
        if "target" in inj:
            t = inj["target"]
            target = LocalhostTarget(
                url=str(t["url"]),
                scheme=str(t.get("scheme") or "http"),
                host=str(t["host"]),
                port=int(t["port"]),
                path=str(t.get("path") or "/"),
                query=str(t.get("query") or ""),
                is_loopback=bool(t.get("is_loopback", True)),
                is_ipv6_literal=bool(t.get("is_ipv6_literal", False)),
            )
        else:
            target = parse_localhost_target(
                url=url,
                host=host,
                port=port,
                path=path,
                allow_non_loopback=allow_non_loopback,
            )
    except TargetValidationError as exc:
        report = {
            "schema_version": "wnt.localhost_diagnose.v1",
            "command": "localhost-diagnose",
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp_utc": _now(),
            "tool_version": __version__,
            "validation_error": exc.to_dict(),
            "classification": {
                "code": "UNKNOWN_LOCALHOST_FAILURE",
                "confidence": 0.0,
                "proof_tier": "T0",
            },
            "policy": policy_envelope(remediation_requested=False),
            "limitations": ["Target validation failed before probes ran."],
            "errors": [exc.to_dict()],
        }
        return attach_governance_envelope(report, dry_run=True, requires_confirmation=True)

    # Resolution
    if "resolution" in inj:
        from .resolution import ResolutionEvidence

        r = inj["resolution"]
        resolution = ResolutionEvidence(
            host=str(r.get("host") or target.host),
            ipv4=list(r.get("ipv4") or []),
            ipv6=list(r.get("ipv6") or []),
            has_127_0_0_1=bool(r.get("has_127_0_0_1")),
            has_ipv6_loopback=bool(r.get("has_ipv6_loopback")),
            errors=list(r.get("errors") or []),
            hosts_file_mentions=list(r.get("hosts_file_mentions") or []),
            timestamp_utc=str(r.get("timestamp_utc") or _now()),
        )
    else:
        resolution = resolve_localhost_host(target.host)

    addresses = loopback_probe_addresses(resolution)

    # TCP
    if "tcp_probes" in inj:
        from .tcp_probe import TcpProbeResult

        tcp_probes = [
            TcpProbeResult(
                address=str(p["address"]),
                address_family=str(p.get("address_family") or "IPv4"),
                port=int(p.get("port") or target.port),
                connect_success=bool(p.get("connect_success")),
                elapsed_ms=float(p.get("elapsed_ms") or 0),
                error_category=str(p.get("error_category") or "UNKNOWN_SOCKET_ERROR"),
                windows_error_code=p.get("windows_error_code"),
                detail=str(p.get("detail") or ""),
                timestamp_utc=str(p.get("timestamp_utc") or _now()),
            )
            for p in inj["tcp_probes"]
        ]
    else:
        tcp_probes = tcp_probe_many(addresses, target.port, timeout=timeout)

    tcp_any = any(p.connect_success for p in tcp_probes)

    # Listeners
    listeners = discover_listeners(
        target.port,
        run=run,
        timeout=max(timeout, 10.0),
        inject=inj.get("listeners"),
        second_pass="listeners" not in inj,
    )

    # Processes
    processes = []
    if include_process or inj.get("processes") is not None:
        proc_inject = inj.get("processes")
        if isinstance(proc_inject, list):
            for row in proc_inject:
                processes.append(
                    collect_process_evidence(
                        int(row.get("pid") or 0),
                        run=run,
                        inject=row,
                    )
                )
        else:
            pids = sorted({r.pid for r in listeners.listeners if r.pid is not None})
            for pid in pids:
                processes.append(collect_process_evidence(pid, run=run, timeout=max(timeout, 10.0)))

    access_denied = any(
        "access" in e.lower() or "denied" in e.lower()
        for p in processes
        for e in (p.collection_errors + p.access_denied_fields)
    )

    # HTTP only after TCP success
    http_probes = []
    proxy_comparison = None
    if include_http or include_proxy_comparison or inj.get("http_probes") is not None:
        if "http_probes" in inj:
            from .http_probe import HttpProbeResult

            for h in inj["http_probes"]:
                http_probes.append(
                    HttpProbeResult(
                        mode=str(h.get("mode") or "direct"),
                        requested_url=str(h.get("requested_url") or target.url),
                        effective_url=h.get("effective_url"),
                        status_code=h.get("status_code"),
                        response_headers=dict(h.get("response_headers") or {}),
                        elapsed_ms=float(h.get("elapsed_ms") or 0),
                        redirect_chain=list(h.get("redirect_chain") or []),
                        exception_category=h.get("exception_category"),
                        detail=str(h.get("detail") or ""),
                        success=bool(h.get("success")),
                        timestamp_utc=str(h.get("timestamp_utc") or _now()),
                    )
                )
        elif tcp_any:
            direct = http_probe_direct(target.url, timeout=timeout)
            http_probes.append(direct)
            if include_proxy_comparison:
                proxy_url = None
                # Prefer explicit WinINET localhost proxy if present later
                proxy_http = http_probe_proxy_aware(
                    target.url, timeout=timeout, proxy_url=proxy_url
                )
                http_probes.append(proxy_http)
                proxy_comparison = compare_http_probes(direct, proxy_http)
        else:
            warnings.append("HTTP probes skipped because no TCP connect succeeded.")

    direct_ok = next((h.success for h in http_probes if h.mode == "direct"), None)
    proxy_ok = next((h.success for h in http_probes if h.mode == "proxy_aware"), None)

    proxy_ev = collect_proxy_evidence(
        run=run,
        timeout=max(timeout, 10.0),
        inject=inj.get("proxy_evidence"),
        target_port=target.port,
        tcp_any_success=tcp_any,
        http_direct_ok=direct_ok,
        http_proxy_ok=proxy_ok,
    )

    nearby = []
    if include_nearby_listeners or inj.get("nearby_listeners") is not None:
        nearby = discover_nearby_listeners(
            target_port=target.port,
            known_listeners=listeners.listeners,
            processes=processes,
            run=run,
            inject=inj.get("nearby_listeners"),
        )

    classification = classify_localhost_failure(
        resolution_errors=list(resolution.errors),
        tcp_probes=tcp_probes,
        listeners=listeners,
        http_probes=http_probes,
        proxy=proxy_ev,
        nearby_count=len(nearby),
        prior_listener_evidence=prior_listener_evidence or bool(inj.get("prior_listener_evidence")),
        access_denied=access_denied,
    )

    ipv4_only = bool(listeners.listeners) and all(
        r.address_family == "IPv4" for r in listeners.listeners
    )
    ipv6_only = bool(listeners.listeners) and all(
        r.address_family == "IPv6" for r in listeners.listeners
    )

    remediations = []
    if remediation_preview:
        remediations = build_remediation_preview(
            classification,
            target_url=target.url,
            ipv4_only_listener=ipv4_only,
            ipv6_only_listener=ipv6_only,
            nearby_ports=[n.local_port for n in nearby],
            service_name=inj.get("service_name"),
        )

    policy = policy_envelope(remediation_requested=remediation_preview)

    report: dict[str, Any] = {
        "schema_version": "wnt.localhost_diagnose.v1",
        "command": "localhost-diagnose",
        "event_id": event_id,
        "correlation_id": correlation_id,
        "timestamp_utc": _now(),
        "tool_version": __version__,
        "target": target.to_dict(),
        "resolution": resolution.to_dict(),
        "tcp_probes": [p.to_dict() for p in tcp_probes],
        "listeners": listeners.to_dict(),
        "processes": [p.to_dict() for p in processes],
        "http_probes": [h.to_dict() for h in http_probes],
        "proxy_evidence": proxy_ev.to_dict(),
        "proxy_comparison": proxy_comparison,
        "nearby_listeners": [n.to_dict() for n in nearby],
        "classification": classification.to_dict(),
        "policy": policy,
        "remediation_preview": [r.to_dict() for r in remediations],
        "limitations": list(classification.limitations),
        "warnings": warnings,
        "errors": errors,
        "collection_options": {
            "timeout": timeout,
            "include_process": include_process,
            "include_http": include_http,
            "include_proxy_comparison": include_proxy_comparison,
            "include_nearby_listeners": include_nearby_listeners,
            "remediation_preview": remediation_preview,
            "verbose": verbose,
        },
    }
    report = attach_governance_envelope(report, dry_run=True, requires_confirmation=True)

    ok, audit_err = append_audit_dict(
        {
            "event_type": "localhost_diagnose",
            "event_id": event_id,
            "correlation_id": correlation_id,
            "target_url": target.url,
            "host": target.host,
            "port": target.port,
            "classification": classification.code,
            "proof_tier": classification.proof_tier,
            "confidence": classification.confidence,
            "policy_decision": policy.get("decision"),
            "tool_version": __version__,
        },
        log_name="localhost-diagnose.jsonl",
    )
    if not ok and audit_err:
        report.setdefault("warnings", []).append(f"audit_write_failed: {audit_err}")

    if evidence_out:
        out_path = Path(evidence_out)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            report.setdefault("errors", []).append(
                {"code": "EVIDENCE_OUT_FAILED", "message": str(exc)}
            )

    return report


def render_localhost_diagnose(report: dict[str, Any], *, as_json: bool, verbose: bool) -> str:
    """Render a diagnose *report* as human-readable text or compact JSON.

    Args:
        report: Full output dict from ``run_localhost_diagnose``.
        as_json: When ``True``, returns pretty-printed JSON with a trailing
            newline.  When ``False``, returns the operator summary from
            ``format_localhost_diagnose_human``.
        verbose: When ``True`` and ``as_json`` is ``False``, appends the full
            JSON block after the human summary.  Ignored when ``as_json`` is
            ``True`` or when the report contains a ``validation_error``.

    Returns:
        A string suitable for ``sys.stdout.write`` or logging.
    """

    if as_json:
        return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    text = format_localhost_diagnose_human(report)
    if verbose and "validation_error" not in report:
        text += "\n" + json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    return text
