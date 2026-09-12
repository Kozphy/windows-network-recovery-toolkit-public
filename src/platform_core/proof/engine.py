"""Direct vs proxied proof engine — observation != proof.

Module responsibility:
    Runs a structured multi-probe suite (DNS, TCP, direct HTTP, system-proxy HTTP,
    and optionally explicit-proxy HTTP) against a target URL to produce contrasting
    path evidence.  The outcome classifies the connectivity pattern into a
    ``ProofOutcome`` (e.g. ``DEAD_LOCALHOST_PROXY``,
    ``LOCAL_PROXY_UPSTREAM_FAILURE``) without claiming malware attribution or
    MITM confirmation.

System placement:
    Called by the ``diagnose --proof`` CLI command and the ``/platform/proof``
    API route.  Probes are executed via ``subprocess.run`` (injectable via the
    ``run`` parameter for fixture-based testing).  No state is written to registry,
    files, or network configuration.

Key invariants:
    - ``run_proof_engine`` is read-only; it does not mutate any host configuration.
    - The ``inject`` parameter bypasses all probes and deserialises a
      ``ProofResult`` directly — used exclusively in fixture-based tests.
    - ``is_proof`` in the returned ``ProofResult`` is ``True`` only when contrasting
      evidence (e.g. direct succeeds, proxied 502) provides a bounded causal
      conclusion; otherwise ``False``.
    - Each probe observation carries its own ``limitations[]`` asserting that TCP
      success ≠ HTTP success and HTTP success ≠ root-cause proof.

Side effects:
    Executes ``nslookup``, ``powershell Test-NetConnection``, and ``curl`` as child
    processes when not using fixture injection.  Network traffic is generated; no
    host state is modified.

Failure modes:
    ``subprocess.TimeoutExpired`` and ``OSError`` (missing executables) are caught
    per probe and recorded as failed observations rather than propagated to the
    caller.
"""

from __future__ import annotations

import re
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from .models import ProofObservation, ProofOutcome, ProofResult


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_cmd(argv: list[str], *, run: Callable[..., Any], timeout: float) -> tuple[int, str]:
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
        return int(proc.returncode), ((proc.stdout or "") + (proc.stderr or "")).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _parse_http_status(code: int, out: str) -> int | None:
    if code != 0:
        return None
    m = re.search(r"(\d{3})\s*$", out.strip())
    return int(m.group(1)) if m else None


def _probe_dns(host: str, *, run: Callable[..., Any], timeout: float) -> ProofObservation:
    code, out = _run_cmd(["nslookup", host], run=run, timeout=timeout)
    addresses = re.findall(r"Address:\s*(\S+)", out)
    ok = code == 0 and bool(addresses)
    return ProofObservation(
        probe_id="dns",
        probe_type="dns_resolution",
        observed_value=",".join(addresses) if addresses else "unresolved",
        success=ok,
        raw_excerpt=out[:400],
        limitations=["DNS success does not prove HTTP path success."],
    )


def _probe_tcp(
    host: str, port: int, *, run: Callable[..., Any], timeout: float
) -> ProofObservation:
    ps = (
        f"Test-NetConnection -ComputerName {host} -Port {port} "
        f"-WarningAction SilentlyContinue | Select-Object -ExpandProperty TcpTestSucceeded"
    )
    code, out = _run_cmd(["powershell", "-NoProfile", "-Command", ps], run=run, timeout=timeout)
    ok = code == 0 and "true" in out.lower()
    return ProofObservation(
        probe_id="tcp",
        probe_type="tcp_connect",
        observed_value=f"{host}:{port}={ok}",
        success=ok,
        raw_excerpt=out[:200],
        limitations=["TCP connect success does not prove TLS/HTTP success."],
    )


def _probe_http(
    url: str,
    *,
    mode: str,
    proxy_server: str | None,
    run: Callable[..., Any],
    timeout: float,
) -> ProofObservation:
    argv = [
        "curl",
        "-sS",
        "-o",
        "NUL",
        "-w",
        "%{http_code}",
        "-L",
        "--max-time",
        str(int(timeout)),
    ]
    if mode == "direct":
        argv.extend(["--noproxy", "*"])
    elif mode == "explicit" and proxy_server:
        argv.extend(["--proxy", proxy_server])
    argv.append(url)
    code, out = _run_cmd(argv, run=run, timeout=timeout + 5)
    status = _parse_http_status(code, out)
    ok = status is not None and status < 500
    return ProofObservation(
        probe_id=f"http_{mode}",
        probe_type=f"http_{mode}",
        observed_value=str(status or "failed"),
        success=ok,
        raw_excerpt=out[:100],
        limitations=[f"HTTP {mode} probe is path observation, not root-cause proof."],
    )


def classify_proof_outcome(
    observations: list[ProofObservation],
    *,
    dead_localhost_proxy: bool = False,
) -> tuple[ProofOutcome, str, str, bool]:
    """Classify proof outcome.

    Args:
        observations: observations supplied by the caller.
        dead_localhost_proxy: dead localhost proxy supplied by the caller.

    Returns:
        The computed `tuple[ProofOutcome, str, str, bool]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    by_id = {o.probe_id: o for o in observations}
    dns = by_id.get("dns")
    tcp = by_id.get("tcp")
    http_direct = by_id.get("http_direct")
    http_system = by_id.get("http_system")
    http_explicit = by_id.get("http_explicit")

    if dead_localhost_proxy:
        return (
            ProofOutcome.DEAD_LOCALHOST_PROXY,
            "ProxyServer points to localhost but no listener is bound.",
            "high",
            False,
        )
    if dns and not dns.success:
        return ProofOutcome.DNS_FAILURE, "DNS resolution failed.", "high", True
    if tcp and not tcp.success:
        return ProofOutcome.TCP_CONNECT_FAILURE, "TCP connect to target failed.", "high", True
    if http_direct and http_system:
        direct_ok = http_direct.success or http_direct.observed_value == "200"
        sys_ok = http_system.success or http_system.observed_value == "200"
        sys_502 = http_system.observed_value in {"502", "504"}
        if direct_ok and sys_502:
            return (
                ProofOutcome.LOCAL_PROXY_UPSTREAM_FAILURE,
                "Direct path succeeds; system-proxy path returns 502/504 — local proxy/upstream failure.",
                "high",
                True,
            )
        if not direct_ok and not sys_ok:
            if http_direct.observed_value in {"0", "failed", "None"}:
                return (
                    ProofOutcome.TLS_OR_HTTP_FAILURE,
                    "HTTP probes failed on direct and proxied paths.",
                    "medium",
                    False,
                )
            return (
                ProofOutcome.REMOTE_SERVER_FAILURE,
                "Both direct and proxied paths fail — likely remote/upstream.",
                "medium",
                False,
            )
    if http_explicit and not http_explicit.success and http_direct and http_direct.success:
        return (
            ProofOutcome.LOCAL_PROXY_UPSTREAM_FAILURE,
            "Explicit proxy path fails while direct path succeeds.",
            "high",
            True,
        )
    return (
        ProofOutcome.UNKNOWN_INCONCLUSIVE,
        "Insufficient contrasting proof to classify.",
        "low",
        False,
    )


def run_proof_engine(
    url: str,
    *,
    proxy_server: str | None = None,
    dead_localhost_proxy: bool = False,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: dict[str, Any] | None = None,
) -> ProofResult:
    """Run direct vs proxied proof suite. Read-only — no host mutation."""
    if inject:
        return ProofResult.model_validate(inject)

    run_fn = run or subprocess.run
    target = urlparse(url)
    host = target.hostname or ""
    port = target.port or (443 if target.scheme == "https" else 80)

    observations = [
        _probe_dns(host, run=run_fn, timeout=timeout),
        _probe_tcp(host, port, run=run_fn, timeout=timeout),
        _probe_http(url, mode="direct", proxy_server=None, run=run_fn, timeout=timeout),
        _probe_http(url, mode="system", proxy_server=None, run=run_fn, timeout=timeout),
    ]
    if proxy_server:
        observations.append(
            _probe_http(
                url, mode="explicit", proxy_server=proxy_server, run=run_fn, timeout=timeout
            )
        )

    outcome, rationale, confidence, is_proof = classify_proof_outcome(
        observations,
        dead_localhost_proxy=dead_localhost_proxy,
    )
    return ProofResult(
        proof_id=f"proof-{uuid.uuid4().hex[:12]}",
        timestamp_utc=_now(),
        target_url=url,
        observations=observations,
        outcome=outcome,
        outcome_rationale=rationale,
        confidence_level=confidence,
        limitations=[
            "Proof engine contrasts paths; it does not identify malware.",
            "502 from upstream is observation until writer proof exists.",
        ],
        is_proof=is_proof,
    )
