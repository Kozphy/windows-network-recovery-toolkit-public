"""Deterministic root-cause scoring over a normalized ``FeatureVector`` (legacy v1 buckets).

Maps Windows connectivity/proxy/socket signals onto fixed hypothesis keys via additive
confidence bumps followed by `[0.0, 1.0]` clamping (`_clamp`). Outputs are intentionally
readable for plaintext reports and audit JSONL—not trained models.

Pipeline position:
    ``src.diagnostics.collector`` / fixtures → ``score_root_causes`` →
    ``src.recommendations.build_recommendations`` and CLI payloads.

Inputs:
    Immutable `FeatureVector` only; malformed inputs should be corrected at collection time.

Outputs:
    `DecisionResult` with per-cause `CauseScore` records including evidence bullets.

Raises:
    `score_root_causes` raises no exceptions; rule logic tolerates ambiguous signals by
    producing lower confidences."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..diagnostics.features import FeatureVector

RootCauseKey = Literal[
    "dns_issue",
    "proxy_issue",
    "winsock_issue",
    "firewall_issue",
    "network_adapter_issue",
    "isp_router_issue",
    "browser_only_issue",
]

ALL_CAUSES: tuple[RootCauseKey, ...] = (
    "dns_issue",
    "proxy_issue",
    "winsock_issue",
    "firewall_issue",
    "network_adapter_issue",
    "isp_router_issue",
    "browser_only_issue",
)

_CONNECTION_TW_SPIKE = 5000
_CONNECTION_EST_SPIKE = 8000


def _clamp(x: float) -> float:
    """Clamp intermediate confidence sums to `[0.0, 1.0]`.

    Args:
        x: Unbounded additive score aggregate.

    Returns:
        Bounded float suitable for persisted confidence fields.
    """
    return max(0.0, min(1.0, x))


@dataclass(frozen=True)
class CauseScore:
    """Per-cause confidence and evidence bundle.

    Attributes:
        cause: Canonical root-cause key.
        confidence: Confidence score in [0.0, 1.0].
        evidence: Evidence statements supporting score adjustments.
    """

    cause: RootCauseKey
    confidence: float
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class DecisionResult:
    """Container for full decision-scoring outcome."""

    scores_by_cause: dict[RootCauseKey, CauseScore]

    def ranked(self) -> list[CauseScore]:
        """Return cause scores sorted by descending confidence."""
        return sorted(
            self.scores_by_cause.values(),
            key=lambda s: (-s.confidence, s.cause),
        )

    def primary(self) -> CauseScore:
        """Return highest-confidence cause score.

        Returns:
            Top ``CauseScore`` from `ranked()`, or a low-confidence ``browser_only_issue``
            sentinel when the ranked list is empty.

        Note:
            ``score_root_causes`` always emits one entry per ``ALL_CAUSES`` key, so the empty
            ranking path is defensive-only.
        """
        r = self.ranked()
        return r[0] if r else CauseScore("browser_only_issue", 0.05, ("No signals collected.",))


def score_root_causes(features: FeatureVector) -> DecisionResult:
    """Score all root-cause hypotheses from collected feature vector.

    Decision intent:
        Provide an explainable confidence ladder instead of a single opaque
        classification so operators can validate alternatives.

    Constraints and limitations:
        - Heuristic weighting is manually tuned and environment-sensitive.
        - Multiple simultaneous failures can produce closely ranked outcomes.

    Side effects:
        None.

    Idempotency:
        Fully idempotent for identical feature input.

    Audit Notes:
        - What can go wrong: signal ambiguity causes lower-confidence ranking.
        - Detection: review `evidence` per cause and compare with raw probes.
        - Recovery: rerun diagnostics, use fixture replay, adjust weights via
          code review if systematic misclassification is observed.

    Args:
        features: Normalized diagnostic feature vector.

    Returns:
        DecisionResult: Confidence-scored hypotheses for all known causes.
    """
    deltas: dict[RootCauseKey, float] = {c: 0.06 for c in ALL_CAUSES}  # small prior
    evidence: dict[RootCauseKey, list[str]] = {c: [] for c in ALL_CAUSES}

    def bump(cause: RootCauseKey, amount: float, note: str) -> None:
        """Add evidence-weighted increment to ``deltas[cause]`` and attach ``note``.

        Args:
            cause: Hypothesis bucket receiving the adjustment.
            amount: Confidence increment before eventual clamp in the outer loop.
            note: Evidence string surfaced in audits and plaintext exports.

        Raises:
            None.
        """
        deltas[cause] += amount
        evidence[cause].append(note)

    # Exhaustion / churn — strengthens ISP/router or stack instability hypotheses.
    if (
        features.time_wait_count >= _CONNECTION_TW_SPIKE
        or features.established_count >= _CONNECTION_EST_SPIKE
    ):
        ratio = max(
            features.time_wait_count / max(_CONNECTION_TW_SPIKE, 1),
            features.established_count / max(_CONNECTION_EST_SPIKE, 1),
        )
        bump("isp_router_issue", _clamp(0.35 + 0.25 * ratio), "High TIME_WAIT / ESTABLISHED counts observed.")

    # Adapter / link
    if not features.adapter_connected:
        bump(
            "network_adapter_issue",
            0.78,
            "No physical adapter reported Up — local link/driver state may block traffic.",
        )

    # Gateway segment
    if features.gateway_reachable is False:
        bump(
            "isp_router_issue",
            0.62,
            "Default gateway ping failed — local LAN segment or router path is suspect.",
        )
    elif features.gateway_reachable is True and not features.ping_ip_ok:
        bump(
            "isp_router_issue",
            0.55,
            "Gateway responds but WAN ping failed — ISP/upstream outage is plausible.",
        )

    if not features.ping_ip_ok and features.gateway_reachable is not False:
        bump(
            "network_adapter_issue",
            0.45,
            "ICMP to a public resolver failed — verify cabling, Wi‑Fi association, or VPN tunnel state.",
        )

    # DNS
    if features.ping_ip_ok and not features.nslookup_ok:
        bump("dns_issue", 0.78, "IP reachability succeeds while nslookup google.com fails.")
        if features.ping_domain_ok:
            bump("dns_issue", 0.08, "Ping to a hostname succeeded alongside nslookup failure — intermittent resolver behavior.")

    elif not features.ping_domain_ok and features.ping_ip_ok:
        bump("dns_issue", 0.55, "Ping to hostname failed while ping to numeric IP succeeded — name resolution degraded.")

    if features.dns_servers_detected == 0 and features.adapter_connected:
        bump(
            "dns_issue",
            0.35,
            "No DNS servers were enumerated from ipconfig — verify adapter IPv4 DNS configuration.",
        )

    # Proxy
    if features.proxy_enabled and not features.browser_http_ok:
        bump(
            "proxy_issue",
            0.74,
            "Proxy signals are active and HTTPS probing via curl failed — consistent with proxy misrouting.",
        )
    elif features.proxy_enabled:
        bump("proxy_issue", 0.32, "Proxy configuration detected while application-layer HTTPS probe succeeded.")

    # Firewall / filtering path (conservative — never triggers automatic resets)
    if features.firewall_path_suspected:
        bump(
            "firewall_issue",
            0.52,
            "TCP 443 succeeds but HTTPS failed without TLS fingerprints, or winhttp text hints at blocking — review firewall/security products manually.",
        )
    elif features.tls_cert_issue_detected:
        bump(
            "firewall_issue",
            0.42,
            "TLS/certificate keywords appeared in HTTPS probe output — inspect AV SSL inspection or trust store issues manually.",
        )

    # Winsock/stack corruption heuristic
    stacked_failures = (
        int(not features.ping_ip_ok)
        + int(not features.nslookup_ok)
        + int(not features.tcp_443_ok)
        + int(not features.browser_http_ok)
    )
    if stacked_failures >= 3:
        bump(
            "winsock_issue",
            0.6,
            "Multiple independent transports failed simultaneously — Winsock/driver corruption is plausible after confirming hardware/link health.",
        )
    elif not features.tcp_443_ok and features.ping_ip_ok and features.nslookup_ok:
        bump(
            "winsock_issue",
            0.38,
            "TCP 443 to a known endpoint failed while ICMP/DNS probes succeeded — Winsock/stack or middlebox filtering possible.",
        )

    # Browser-only / app layer (systems looks healthy via automated probes)
    if (
        features.ping_ip_ok
        and features.nslookup_ok
        and features.tcp_443_ok
        and features.browser_http_ok
        and not features.proxy_enabled
        and stacked_failures == 0
    ):
        bump(
            "browser_only_issue",
            0.48,
            "Automated ICMP/DNS/TCP/curl probes succeeded — isolate browser/profile/extensions if symptoms persist only in-browser.",
        )

    # Normalize into per-cause objects
    scored: dict[RootCauseKey, CauseScore] = {}
    for cause in ALL_CAUSES:
        notes = tuple(evidence[cause])
        scored[cause] = CauseScore(cause=cause, confidence=_clamp(deltas[cause]), evidence=notes or ("Baseline prior only.",))

    return DecisionResult(scores_by_cause=scored)


def explain_primary(primary: CauseScore, features: FeatureVector) -> str:
    """Render concise explanation sentence for selected primary cause.

    Args:
        primary: Selected primary cause score.
        features: Feature vector used to construct context markers.

    Returns:
        str: Human-readable summary sentence for reports/UI displays.
    """
    feature_bits = (
        f"ping_ip={'ok' if features.ping_ip_ok else 'fail'}, "
        f"nslookup={'ok' if features.nslookup_ok else 'fail'}, "
        f"curl_https={'ok' if features.browser_http_ok else 'fail'}, "
        f"proxy={'on' if features.proxy_enabled else 'off'}, "
        f"adapter_up={'yes' if features.adapter_connected else 'no'}"
    )
    if primary.evidence and primary.evidence[0] != "Baseline prior only.":
        top = "; ".join(primary.evidence[:3])
        return (
            f"{primary.cause.replace('_', ' ').title()} confidence {primary.confidence:.2f} because {top} "
            f"({feature_bits})."
        )
    return (
        f"{primary.cause.replace('_', ' ').title()} confidence {primary.confidence:.2f} "
        f"({feature_bits}); no strong discriminators fired."
    )
