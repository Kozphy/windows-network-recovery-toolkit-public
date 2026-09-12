"""Typed product contract for the local Endpoint Reliability Platform.

This module backs frontend-visible claims with explicit schemas, read-only probe adapters,
policy labels, append-only audit rows, and replayable diagnosis records. It is intentionally
stdlib-heavy and local-first.
"""

from __future__ import annotations

import hashlib
import json
import platform
import socket
import ssl
import subprocess
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.agent_planner import PolicyBoundary, SafeNextStep
from platform_core.models import utc_now_iso
from platform_core.privacy import stable_endpoint_hash
from platform_core.storage import _path, append_jsonl, find_by_id, iter_jsonl, read_recent_jsonl

ProbeStatus = Literal["ok", "warning", "failed", "unknown"]
EvidenceLevelName = Literal["observation", "inference", "proof"]
PolicyDecisionName = Literal["allow", "preview_only", "blocked"]
EndpointStatus = Literal["healthy", "degraded", "drift_proxy", "unknown"]
PlatformEventKind = Literal[
    "diagnosis_run",
    "correlation_run",
    "remediation_preview",
    "remediation_execute_attempt",
    "remediation_blocked",
    "lkg_snapshot",
    "rollback_preview",
    "agent_next_step",
]
# Planner ``goal`` values (request). Distinct from :data:`SafeNextStep` / response ``next_step``.
AgentNextStep = Literal[
    "suggest_next_probe",
    "rank_hypotheses",
    "explain_risk",
    "generate_remediation_preview",
    "recommend_preview_action",
    "summarize_audit",
    "identify_missing_evidence",
]


class ProbeResult(BaseModel):
    """One typed, timestamped observation from a read-only probe."""

    name: str
    status: ProbeStatus = "unknown"
    observed_value: Any = None
    evidence_level: EvidenceLevelName = "observation"
    timestamp: str = Field(default_factory=utc_now_iso)
    error: str | None = None
    source: str = "placeholder_adapter"


class PolicyResult(BaseModel):
    """Policy outcome attached to diagnoses and previews."""

    decision: PolicyDecisionName
    reason: str
    allowed: bool = False
    required_confirmation: str = ""
    dry_run: bool = True


class DiagnosisResult(BaseModel):
    """Frontend-facing diagnosis contract with separated evidence layers."""

    run_id: str
    endpoint_id: str
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    observations: list[ProbeResult] = Field(default_factory=list)
    inferred_hypotheses: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    evidence_level: EvidenceLevelName = "observation"
    recommended_next_test: str = ""
    policy_result: PolicyResult
    audit_event_id: str
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)


class EndpointSummary(BaseModel):
    """Fleet endpoint row shown in dashboards."""

    endpoint_id: str
    hostname_hash: str = ""
    safe_display_name: str = ""
    os: str = ""
    status: EndpointStatus = "unknown"
    last_seen_at: str = ""
    last_known_good_available: bool = False
    latest_risk_score: float = 0.0
    latest_diagnosis_id: str = ""


class PlatformAuditEvent(BaseModel):
    """Append-only platform audit row with replay correlation fields."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=utc_now_iso)
    endpoint_id: str = ""
    event_kind: PlatformEventKind
    observations: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    hypothesis: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    evidence_level: EvidenceLevelName = "observation"
    policy_decision: str = ""
    actor: str = "platform"
    replay_ref: str = ""
    run_id: str = ""
    previous_hash: str = ""
    hash: str = ""


class DiagnosisRunRequest(BaseModel):
    """Optional knobs for a local read-only diagnosis run."""

    endpoint_id: str | None = None
    include_live_probes: bool = True


class RemediationContractResponse(BaseModel):
    """Normalized remediation response fields layered onto existing previews/executions."""

    action_id: str
    allowed: bool
    decision: PolicyDecisionName
    reason: str
    required_confirmation: str = ""
    audit_event_id: str
    dry_run: bool = True


class LkgSnapshotRequest(BaseModel):
    """Represent LkgSnapshotRequest data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    endpoint_id: str
    snapshot: dict[str, Any] = Field(default_factory=dict)
    source: str = "operator_snapshot"


class RollbackPreviewRequest(BaseModel):
    """Represent RollbackPreviewRequest data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    endpoint_id: str
    target_snapshot_id: str | None = None
    fields: list[str] = Field(
        default_factory=lambda: [
            "ProxyEnable",
            "ProxyServer",
            "AutoConfigURL",
            "ProxyOverride",
            "AutoDetect",
        ]
    )


class AgentNextStepRequest(BaseModel):
    """Represent AgentNextStepRequest data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    endpoint_id: str | None = None
    run_id: str | None = None
    goal: AgentNextStep = "suggest_next_probe"
    context: dict[str, Any] = Field(default_factory=dict)


class AgentNextStepResponse(BaseModel):
    """API response for agent next-step; ``next_step`` matches :data:`SafeNextStep` from the planner."""

    next_step: SafeNextStep = "run_diagnosis"
    reason: str
    evidence_used: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    policy_boundary: PolicyBoundary = "recommendation_only_no_mutation"
    blocked_actions: list[str] = Field(default_factory=list)


def local_endpoint_id() -> str:
    """Return a privacy-preserving stable id for the current host."""

    return stable_endpoint_hash(platform.node(), platform.release(), None)


def _run(argv: list[str], timeout_seconds: float = 8.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            shell=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return -1, "", str(exc)
    except OSError as exc:
        return -1, "", str(exc)
    return int(proc.returncode), proc.stdout or "", proc.stderr or ""


def probe_dns() -> ProbeResult:
    """Resolve a known host using the local resolver without mutating system state."""

    try:
        addrs = socket.getaddrinfo("www.microsoft.com", 443, type=socket.SOCK_STREAM)
        return ProbeResult(
            name="dns_probe",
            status="ok" if addrs else "warning",
            observed_value={"host": "www.microsoft.com", "address_count": len(addrs)},
            source="socket.getaddrinfo",
        )
    except OSError as exc:
        return ProbeResult(
            name="dns_probe", status="failed", error=str(exc), source="socket.getaddrinfo"
        )


def probe_tcp_443() -> ProbeResult:
    """Open a bounded TCP connection to validate transport reachability."""

    try:
        with socket.create_connection(("www.microsoft.com", 443), timeout=5):
            return ProbeResult(
                name="tcp_443_probe",
                status="ok",
                observed_value="connected",
                source="socket.create_connection",
            )
    except OSError as exc:
        return ProbeResult(
            name="tcp_443_probe", status="failed", error=str(exc), source="socket.create_connection"
        )


def probe_https() -> ProbeResult:
    """Perform a minimal TLS handshake as HTTPS-path evidence."""

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("www.microsoft.com", 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname="www.microsoft.com") as tls:
                return ProbeResult(
                    name="https_probe",
                    status="ok",
                    observed_value={
                        "tls_version": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                    },
                    source="ssl.wrap_socket",
                )
    except OSError as exc:
        return ProbeResult(
            name="https_probe", status="failed", error=str(exc), source="ssl.wrap_socket"
        )
    except ssl.SSLError as exc:
        return ProbeResult(
            name="https_probe", status="failed", error=str(exc), source="ssl.wrap_socket"
        )


def probe_wininet_proxy() -> ProbeResult:
    """Read WinINET proxy state through the existing local-first collector."""

    try:
        from proxy_guard.proxy_signal_collector import collect_proxy_signals

        signals = collect_proxy_signals()
        status: ProbeStatus = "ok"
        if signals.get("limitations"):
            status = "warning"
        return ProbeResult(
            name="wininet_proxy_state",
            status=status,
            observed_value={
                "proxy_enable": signals.get("proxy_enable"),
                "proxy_server": signals.get("proxy_server"),
                "auto_config_url": signals.get("auto_config_url"),
                "proxy_override": signals.get("proxy_override"),
                "auto_detect": signals.get("auto_detect"),
            },
            source="proxy_guard.proxy_signal_collector",
            error="; ".join(str(x) for x in signals.get("limitations") or []) or None,
        )
    except Exception as exc:  # collector must never bring down diagnosis contract
        return ProbeResult(
            name="wininet_proxy_state",
            status="unknown",
            error=str(exc),
            source="proxy_guard.proxy_signal_collector",
        )


def probe_winhttp_proxy() -> ProbeResult:
    """Read WinHTTP proxy using netsh when available."""

    code, out, err = _run(["netsh", "winhttp", "show", "proxy"])
    if code == 0:
        return ProbeResult(
            name="winhttp_proxy_state",
            status="ok",
            observed_value=out.strip()[:2000],
            source="netsh winhttp show proxy",
        )
    return ProbeResult(
        name="winhttp_proxy_state",
        status="unknown",
        error=(err or out)[:1000],
        source="netsh winhttp show proxy",
    )


def probe_localhost_listener(wininet: ProbeResult | None = None) -> ProbeResult:
    """Return listener ownership hints for localhost proxy ports; candidate only, not writer proof."""

    observed = wininet.observed_value if wininet else {}
    port: int | None = None
    server = ""
    if isinstance(observed, dict):
        server = str(observed.get("proxy_server") or "")
    if server:
        try:
            from proxy_guard.proxy_signal_collector import parse_proxy_server

            parsed = parse_proxy_server(server)
            raw_port = parsed.get("localhost_port")
            port = int(raw_port) if isinstance(raw_port, int) else None
        except Exception:
            port = None
    if port is None:
        return ProbeResult(
            name="localhost_proxy_listener",
            status="unknown",
            observed_value={"candidate_actor": None, "basis": "no_localhost_proxy_port"},
            source="proxy_guard.port_process_attribution",
        )
    try:
        from proxy_guard.port_process_attribution import attribute_proxy_port

        attr = attribute_proxy_port(port)
        return ProbeResult(
            name="localhost_proxy_listener",
            status="ok" if attr.get("pid") else "warning",
            observed_value={
                "candidate_actor": attr,
                "proof_boundary": "listener_correlation_not_registry_writer",
            },
            source="proxy_guard.port_process_attribution",
        )
    except Exception as exc:
        return ProbeResult(
            name="localhost_proxy_listener",
            status="unknown",
            error=str(exc),
            source="proxy_guard.port_process_attribution",
        )


def probe_git_npm_proxy() -> ProbeResult:
    """Check common developer proxy configuration surfaces via read-only commands."""

    git_code, git_out, git_err = _run(
        ["git", "config", "--global", "--get-regexp", "proxy"], timeout_seconds=5.0
    )
    npm_code, npm_out, npm_err = _run(["npm", "config", "get", "proxy"], timeout_seconds=5.0)
    observed = {
        "git_proxy_config": git_out.strip() if git_code == 0 else "",
        "npm_proxy": npm_out.strip() if npm_code == 0 else "",
    }
    errs = [x for x in (git_err.strip(), npm_err.strip()) if x]
    status: ProbeStatus = "ok" if any(observed.values()) else "unknown"
    return ProbeResult(
        name="git_npm_proxy_config",
        status=status,
        observed_value=observed,
        error="; ".join(errs)[:1000] if errs else None,
        source="git/npm config read",
    )


def latest_lkg_snapshot(endpoint_id: str) -> dict[str, Any] | None:
    """Return latest endpoint-specific LKG snapshot row."""

    latest: dict[str, Any] | None = None
    for row in iter_jsonl(_path("lkg_snapshots.jsonl")):
        if row.get("endpoint_id") == endpoint_id:
            latest = row
    return latest


def probe_lkg_available(endpoint_id: str) -> ProbeResult:
    """Report whether a last-known-good snapshot is available."""

    row = latest_lkg_snapshot(endpoint_id)
    return ProbeResult(
        name="lkg_snapshot_available",
        status="ok" if row else "warning",
        observed_value={
            "available": bool(row),
            "snapshot_id": row.get("snapshot_id") if row else None,
        },
        source="platform_data/lkg_snapshots.jsonl",
    )


def collect_probe_results(endpoint_id: str, *, include_live: bool = True) -> list[ProbeResult]:
    """Collect the typed probes implied by the frontend product contract."""

    if not include_live:
        return [probe_lkg_available(endpoint_id)]
    wininet = probe_wininet_proxy()
    return [
        probe_dns(),
        probe_tcp_443(),
        probe_https(),
        wininet,
        probe_winhttp_proxy(),
        probe_localhost_listener(wininet),
        probe_git_npm_proxy(),
        probe_lkg_available(endpoint_id),
    ]


def classify_diagnosis(
    observations: list[ProbeResult],
) -> tuple[list[str], float, float, EvidenceLevelName, str, PolicyResult]:
    """Derive hypotheses and policy from observations without claiming proof."""

    hypotheses: list[str] = []
    risk = 0.0
    confidence = 0.35
    next_test = "Collect another snapshot or run targeted proof probe."
    policy = PolicyResult(
        decision="allow", reason="read_only_diagnosis_only", allowed=True, dry_run=True
    )

    by_name = {p.name: p for p in observations}
    wininet = by_name.get("wininet_proxy_state")
    listener = by_name.get("localhost_proxy_listener")
    https = by_name.get("https_probe")
    tcp = by_name.get("tcp_443_probe")
    dns = by_name.get("dns_probe")

    if dns and dns.status == "failed":
        hypotheses.append("DNS resolution failure can break browser and developer traffic.")
        risk += 0.25
        confidence += 0.15
        next_test = "Run nslookup and compare resolver configuration."
    if tcp and tcp.status == "failed":
        hypotheses.append("TCP 443 path failure suggests transport or policy blocking.")
        risk += 0.25
        confidence += 0.12
        next_test = "Run Test-NetConnection to known HTTPS hosts."
    if tcp and tcp.status == "ok" and https and https.status == "failed":
        hypotheses.append("TCP works but HTTPS fails; TLS/proxy/browser path is suspect.")
        risk += 0.35
        confidence += 0.18
        next_test = "Run direct HTTPS and proxy HTTPS probes and inspect certificate chain."
    if wininet and isinstance(wininet.observed_value, dict):
        enabled = int(wininet.observed_value.get("proxy_enable") or 0)
        server = str(wininet.observed_value.get("proxy_server") or "")
        if enabled == 1 and ("127.0.0.1" in server or "localhost" in server or "::1" in server):
            hypotheses.append("WinINET routes browser traffic through a localhost proxy.")
            risk += 0.45
            confidence += 0.2
            next_test = (
                "Enable Sysmon Event ID 13 or import Procmon trace to identify the registry writer."
            )
            policy = PolicyResult(
                decision="preview_only",
                reason="localhost_proxy_drift_requires_writer_proof_before_remediation",
                allowed=False,
                dry_run=True,
            )
    if listener and isinstance(listener.observed_value, dict):
        candidate = listener.observed_value.get("candidate_actor")
        if isinstance(candidate, dict) and candidate.get("pid"):
            hypotheses.append(
                "A listener PID is time-correlated with the configured localhost proxy port."
            )
            confidence += 0.08
            next_test = (
                "Capture registry writer telemetry; listener ownership is candidate evidence only."
            )

    if not hypotheses:
        hypotheses.append(
            "No high-confidence endpoint reliability issue was inferred from available observations."
        )
        next_test = "Continue monitoring for drift or run a live diagnosis during failure."

    risk = max(0.0, min(1.0, risk))
    confidence = max(0.0, min(1.0, confidence))
    return hypotheses, confidence, risk, "inference", next_test, policy


def append_contract_audit(event: PlatformAuditEvent) -> str:
    """Append a frontend-contract audit event and return its event id."""

    payload = event.model_dump(mode="json")
    previous = ""
    tail = read_recent_jsonl(_path("audit.jsonl"), limit=1)
    if tail:
        previous = str(tail[-1].get("hash") or tail[-1].get("event_hash") or "")
    payload["previous_hash"] = previous
    payload["hash"] = hash_event_payload(payload, previous)
    append_jsonl(_path("audit.jsonl"), payload)
    return event.event_id


def append_diagnosis_run(result: DiagnosisResult) -> None:
    """Persist diagnosis result for latest lookup and replay."""

    append_jsonl(_path("diagnosis_runs.jsonl"), result.model_dump(mode="json"))


def build_diagnosis_run(
    *,
    endpoint_id: str | None = None,
    include_live_probes: bool = True,
    actor: str = "platform_api",
) -> DiagnosisResult:
    """Run read-only diagnosis and persist audit/replay records."""

    eid = endpoint_id or local_endpoint_id()
    observations = collect_probe_results(eid, include_live=include_live_probes)
    hypotheses, confidence, risk, evidence_level, next_test, policy = classify_diagnosis(
        observations
    )
    run_id = str(uuid.uuid4())
    audit_event = PlatformAuditEvent(
        endpoint_id=eid,
        event_kind="diagnosis_run",
        observations=[p.model_dump(mode="json") for p in observations],
        summary="Read-only diagnosis run",
        hypothesis=hypotheses,
        confidence=confidence,
        evidence_level=evidence_level,
        policy_decision=policy.decision,
        actor=actor,
        replay_ref=run_id,
        run_id=run_id,
    )
    audit_id = append_contract_audit(audit_event)
    result = DiagnosisResult(
        run_id=run_id,
        endpoint_id=eid,
        observations=observations,
        inferred_hypotheses=hypotheses,
        confidence=confidence,
        evidence_level=evidence_level,
        recommended_next_test=next_test,
        policy_result=policy,
        audit_event_id=audit_id,
        risk_score=risk,
    )
    append_diagnosis_run(result)
    return result


def get_diagnosis(run_id: str) -> DiagnosisResult | None:
    """Return a stored diagnosis result by run id."""

    row = find_by_id(_path("diagnosis_runs.jsonl"), "run_id", run_id)
    return DiagnosisResult.model_validate(row) if row else None


def latest_diagnosis() -> DiagnosisResult | None:
    """Return newest stored diagnosis result."""

    rows = read_recent_jsonl(_path("diagnosis_runs.jsonl"), limit=1)
    if not rows:
        return None
    return DiagnosisResult.model_validate(rows[-1])


def replay_diagnosis(run_id: str) -> dict[str, Any] | None:
    """Replay a diagnosis from stored observations only; no live probes."""

    diag = get_diagnosis(run_id)
    if diag is None:
        return None
    hypotheses, confidence, risk, evidence_level, next_test, policy = classify_diagnosis(
        diag.observations
    )
    return {
        "run_id": run_id,
        "replay_mode": "stored_observations_only",
        "live_reprobe": False,
        "original": diag.model_dump(mode="json"),
        "recomputed": {
            "inferred_hypotheses": hypotheses,
            "confidence": confidence,
            "risk_score": risk,
            "evidence_level": evidence_level,
            "recommended_next_test": next_test,
            "policy_result": policy.model_dump(mode="json"),
        },
    }


def store_lkg_snapshot(request: LkgSnapshotRequest) -> dict[str, Any]:
    """Append an LKG snapshot record and audit event."""

    snapshot_id = str(uuid.uuid4())
    row = {
        "snapshot_id": snapshot_id,
        "endpoint_id": request.endpoint_id,
        "created_at": utc_now_iso(),
        "source": request.source,
        "snapshot": request.snapshot,
        "reversible_only": True,
    }
    append_jsonl(_path("lkg_snapshots.jsonl"), row)
    append_contract_audit(
        PlatformAuditEvent(
            endpoint_id=request.endpoint_id,
            event_kind="lkg_snapshot",
            summary="LKG snapshot stored",
            policy_decision="allow",
            actor="platform_api",
            replay_ref=snapshot_id,
        )
    )
    return row


def build_rollback_preview(request: RollbackPreviewRequest) -> dict[str, Any]:
    """Build preview-only rollback plan. Does not mutate endpoint state."""

    lkg = latest_lkg_snapshot(request.endpoint_id)
    allowed_fields = {"ProxyEnable", "ProxyServer", "AutoConfigURL", "ProxyOverride", "AutoDetect"}
    fields = [f for f in request.fields if f in allowed_fields]
    decision = "preview_only" if lkg and fields else "blocked"
    reason = (
        "targeted_reversible_wininet_restore_preview"
        if decision == "preview_only"
        else "no_lkg_or_no_safe_fields"
    )
    audit_id = append_contract_audit(
        PlatformAuditEvent(
            endpoint_id=request.endpoint_id,
            event_kind="rollback_preview",
            summary=reason,
            confidence=0.8 if lkg else 0.2,
            evidence_level="observation",
            policy_decision=decision,
            actor="platform_api",
            replay_ref=request.target_snapshot_id or (lkg.get("snapshot_id") if lkg else ""),
        )
    )
    return {
        "action_id": str(uuid.uuid4()),
        "endpoint_id": request.endpoint_id,
        "decision": decision,
        "allowed": False,
        "reason": reason,
        "fields_preview": fields,
        "required_confirmation": "RESTORE_PROXY_LKG" if decision == "preview_only" else "",
        "audit_event_id": audit_id,
        "dry_run": True,
    }


def endpoint_summary(endpoint_id: str, row: dict[str, Any] | None = None) -> EndpointSummary:
    """Build a fleet row by joining heartbeat, diagnosis, and LKG availability."""

    base = row or find_by_id(_path("endpoints.jsonl"), "endpoint_id", endpoint_id) or {}
    latest_for_endpoint: DiagnosisResult | None = None
    for item in iter_jsonl(_path("diagnosis_runs.jsonl")):
        if item.get("endpoint_id") == endpoint_id:
            latest_for_endpoint = DiagnosisResult.model_validate(item)
    risk = latest_for_endpoint.risk_score if latest_for_endpoint else 0.0
    status: EndpointStatus = "unknown"
    if latest_for_endpoint:
        status = "healthy" if risk < 0.25 else ("drift_proxy" if risk >= 0.45 else "degraded")
    os_bits = " ".join(str(base.get(k) or "") for k in ("os_family", "os_version")).strip()
    return EndpointSummary(
        endpoint_id=endpoint_id,
        hostname_hash=endpoint_id,
        safe_display_name=endpoint_id[:12],
        os=os_bits or platform.system(),
        status=status,
        last_seen_at=str(
            base.get("last_seen_at")
            or (latest_for_endpoint.timestamp_utc if latest_for_endpoint else "")
        ),
        last_known_good_available=latest_lkg_snapshot(endpoint_id) is not None,
        latest_risk_score=risk,
        latest_diagnosis_id=latest_for_endpoint.run_id if latest_for_endpoint else "",
    )


def list_endpoint_summaries() -> list[EndpointSummary]:
    """Return endpoint summaries from fleet store when available, else legacy JSONL merge."""

    from platform_core.fleet_store import apply_stale_policy, list_endpoints

    fleet = apply_stale_policy(list_endpoints())
    if fleet:
        out: list[EndpointSummary] = []
        for record in fleet:
            status: EndpointStatus = "unknown"
            if record.risk_state == "healthy":
                status = "healthy"
            elif record.risk_state in ("degraded", "incident_open"):
                status = "degraded"
            elif record.risk_state == "unknown":
                status = "unknown"
            out.append(
                EndpointSummary(
                    endpoint_id=record.endpoint_id,
                    hostname_hash=record.hostname[:16]
                    if record.hostname
                    else record.endpoint_id[:16],
                    safe_display_name=record.endpoint_id[:12],
                    os=record.os_name,
                    status=status,
                    last_seen_at=record.last_seen,
                    last_known_good_available=latest_lkg_snapshot(record.endpoint_id) is not None,
                    latest_diagnosis_id=record.latest_diagnosis_id,
                )
            )
        return out

    seen: dict[str, dict[str, Any]] = {}
    for row in iter_jsonl(_path("endpoints.jsonl")):
        eid = row.get("endpoint_id")
        if isinstance(eid, str):
            seen[eid] = row
    for row in iter_jsonl(_path("diagnosis_runs.jsonl")):
        eid = row.get("endpoint_id")
        if isinstance(eid, str) and eid not in seen:
            seen[eid] = {"endpoint_id": eid}
    if not seen:
        eid = local_endpoint_id()
        seen[eid] = {
            "endpoint_id": eid,
            "os_family": platform.system(),
            "os_version": platform.release(),
            "last_seen_at": utc_now_iso(),
        }
    return [endpoint_summary(eid, row) for eid, row in seen.items()]


def audit_tail(limit: int = 50) -> list[dict[str, Any]]:
    """Return append-only audit tail rows."""

    return read_recent_jsonl(_path("audit.jsonl"), limit=max(1, min(limit, 500)))


def hash_event_payload(payload: dict[str, Any], previous_hash: str = "") -> str:
    """Compute deterministic hash for future hash-chain verification."""

    body = dict(payload)
    body.pop("hash", None)
    encoded = json.dumps(
        {"previous_hash": previous_hash, "event": body}, sort_keys=True, default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
