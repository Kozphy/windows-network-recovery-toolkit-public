"""Data trust aggregates, conflict spotting, partial/false-surface tagging.

Keeps deterministic rules over :class:`~src.core.models.LiveNetworkSnapshot` only.
Proof outcomes are consulted as optional context for degraded-mode signalling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.models import LiveNetworkSnapshot
from ..proof.contracts import ProofResult


@dataclass(frozen=True)
class SignalConflict:
    """A contradiction between observable signals surfaced for audit."""

    code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        """To dict.

        Args:
            None.

        Returns:
            The dict[str, str] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {"code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class TrustAssessment:
    """Per-layer trust 0–1 plus aggregate + operational flags."""

    signal_trust: dict[str, float]
    conflicts: tuple[SignalConflict, ...]
    failure_modes: tuple[str, ...]
    trust_aggregate: float
    degraded_mode: bool
    degraded_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """To dict.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "signal_trust": dict(self.signal_trust),
            "conflicts": [c.to_dict() for c in self.conflicts],
            "failure_modes": list(self.failure_modes),
            "trust_aggregate": round(self.trust_aggregate, 4),
            "degraded_mode": self.degraded_mode,
            "degraded_reasons": list(self.degraded_reasons),
        }


_TRUST_FLOOR_AGGREGATE = 0.42


def assess_trust(
    snapshot: LiveNetworkSnapshot,
    *,
    proof_result: ProofResult | None,
    proofs_requested: bool,
    proof_engine_error: str | None = None,
) -> TrustAssessment:
    """Derive coarse trust scores, contradictions, and FN/FP/partial buckets."""
    fv = snapshot.feature_vector
    reg = snapshot.proxy_registry
    parsed = snapshot.parsed_proxy

    signals: dict[str, float] = {
        "ping_icmp": 0.58,
        "dns_cli_nslookup_like": 0.72,
        "tcp443_connect": 0.78,
        "https_curl_app_stack": 0.64,
        "hkcu_proxy_registry": 0.90
        if reg.proxy_server is not None or reg.proxy_enable is not None
        else 0.50,
        "localhost_listen_inventory": 0.80,
    }

    if snapshot.permission_notes:
        pn = ";".join(snapshot.permission_notes).lower()
        if "permission" in pn or "limited" in pn:
            signals["localhost_listen_inventory"] = min(signals["localhost_listen_inventory"], 0.48)

    failure: list[str] = []
    conflicts: list[SignalConflict] = []

    if fv.ping_ip_ok and fv.nslookup_ok and not fv.tcp_443_ok:
        failure.append("FN_PARTIAL_TRANSPORT_ICMP_DNS_OK_TCP_FAIL")

    if not fv.ping_ip_ok and fv.tcp_443_ok and fv.nslookup_ok:
        failure.append("FP_HEALTHY_SURFACE_ICMP_FILTERED_TRANSPORT_OK")

    if fv.tls_cert_issue_detected and fv.browser_http_ok:
        failure.append("PARTIAL_TLS_HEURISTIC_VS_HTTPS_OK_MISMATCH")

    if reg.proxy_enable == 1 and parsed.is_localhost_proxy and parsed.localhost_port:
        lp = parsed.localhost_port
        if snapshot.localhost_listen_ports and lp not in snapshot.localhost_listen_ports:
            conflicts.append(
                SignalConflict(
                    code="HKCU_PROXY_PORT_NOT_LISTENING",
                    detail=f"ProxyServer references localhost:{lp} but netstat-derived listen set lacks this port.",
                )
            )

    if fv.gateway_reachable is False and fv.ping_ip_ok:
        conflicts.append(
            SignalConflict(
                code="GATEWAY_UNREACHABLE_VS_PUBLIC_PING_OK",
                detail="Default gateway unreachable while WAN IP ICMP appears to succeed.",
            )
        )

    degraded_reasons: list[str] = []

    agg_keys = ("ping_icmp", "dns_cli_nslookup_like", "tcp443_connect", "https_curl_app_stack")
    agg = sum(signals[k] for k in agg_keys) / len(agg_keys)

    if agg < _TRUST_FLOOR_AGGREGATE:
        degraded_reasons.append("TRUST_AGGREGATE_BELOW_FLOOR")

    if len(conflicts) >= 2:
        degraded_reasons.append("MULTI_SIGNAL_CONFLICT")
        degraded_reasons.append("DEGRADED_CAP_ALLOW")

    if proof_engine_error:
        degraded_reasons.append(f"PROOF_ENGINE_EXCEPTION:{proof_engine_error[:160]}")

    proof_degraded_infra = proofs_requested and (
        proof_engine_error is not None or proof_result is None
    )
    if proof_degraded_infra:
        degraded_reasons.append("PROOF_ENGINE_DEGRADED_OR_ABSENT")
    curl_unavail = proof_result is not None and "curl unavailable" in proof_result.summary.lower()

    degraded = (
        agg < _TRUST_FLOOR_AGGREGATE or len(conflicts) >= 2 or proof_degraded_infra or curl_unavail
    )

    return TrustAssessment(
        signal_trust=signals,
        conflicts=tuple(conflicts),
        failure_modes=tuple(failure),
        trust_aggregate=agg,
        degraded_mode=degraded,
        degraded_reasons=tuple(degraded_reasons),
    )
