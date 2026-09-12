"""Classify localhost diagnose findings into structured codes + proof tiers.

Module responsibility:
    Map multi-signal probe evidence (TCP connectivity, listener discovery,
    HTTP comparison, proxy state, resolution errors) to a single primary
    classification code and ordinal proof tier.  Produces a
    ``ClassificationResult`` that is embedded verbatim in every diagnose
    report.

System placement:
    Called exclusively by ``localhost/runner.py``; no OS or subprocess access.
    Tests inject fake probe results to exercise all classification branches
    deterministically.

Key invariants:
    * A high-confidence code never implies certainty — ``limitations[]`` is
      always populated.
    * ``LOCALHOST_PROXY_INTERFERENCE`` requires ``human_review_required=True``
      because proxy-disable is a separate gated command.
    * Proof tiers follow ``src.platform_core.governance.proof_tier.ProofTier``:
      T0 (observation-only) → T4 (operator-confirmed).
    * Classification is deterministic given the same inputs; no randomness.

Side effects:
    None.  Pure function with immutable dataclass output.

Failure modes:
    Falls through to ``UNKNOWN_LOCALHOST_FAILURE`` (T0, confidence=0.4) when
    no higher-confidence branch matches.  Never raises; always returns a result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.platform_core.governance.proof_tier import ProofTier

from .http_probe import HttpProbeResult
from .listeners import ListenerDiscoveryResult
from .proxy_evidence import ProxyEvidence
from .tcp_probe import TcpProbeResult

CLASSIFICATION_CODES = (
    "LOCALHOST_LISTENER_ACTIVE",
    "LOCALHOST_SERVICE_NOT_LISTENING",
    "LOCALHOST_IPV4_IPV6_BIND_MISMATCH",
    "LOCALHOST_PROCESS_EXITED_OR_RESTARTED",
    "LOCALHOST_PORT_CHANGED_POSSIBLE",
    "LOCALHOST_HTTP_APPLICATION_ERROR",
    "LOCALHOST_PROXY_INTERFERENCE",
    "LOCALHOST_ACCESS_DENIED",
    "LOCALHOST_TIMEOUT",
    "LOCALHOST_NAME_RESOLUTION_ERROR",
    "LOCALHOST_TRANSIENT_RACE",
    "UNKNOWN_LOCALHOST_FAILURE",
)


@dataclass
class ClassificationResult:
    """Primary classification output for a single localhost-diagnose run.

    Attributes:
        code: One of ``CLASSIFICATION_CODES``; the primary finding label.
        confidence: Ordinal score in [0, 1].  Not a statistical probability;
            reflects strength of corroborating evidence only.
        proof_tier: Human-readable tier label (e.g. ``"T3"``).
        proof_tier_enum: Corresponding ``ProofTier`` enum value string.
        supporting_evidence_ids: Short identifiers of probes that support
            the classification (e.g. ``["tcp_probes", "listeners"]``).
        contradicting_evidence_ids: Probes whose results weaken the code.
        alternative_hypotheses: Other codes not ruled out by current evidence.
        limitations: Canonical caveats carried into every report.  Never empty
            for any real classification.
        recommended_next_action: Plain-language operator guidance.
        remediation_available: True only when a preview item is offered;
            does NOT imply automatic execution is permitted.
        human_review_required: True when classification outcome demands
            operator confirmation before any downstream action.
    """

    code: str
    confidence: float
    proof_tier: str
    proof_tier_enum: str
    supporting_evidence_ids: list[str] = field(default_factory=list)
    contradicting_evidence_ids: list[str] = field(default_factory=list)
    alternative_hypotheses: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    recommended_next_action: str = ""
    remediation_available: bool = False
    human_review_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "code": self.code,
            "confidence": round(self.confidence, 3),
            "proof_tier": self.proof_tier,
            "proof_tier_enum": self.proof_tier_enum,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "contradicting_evidence_ids": list(self.contradicting_evidence_ids),
            "alternative_hypotheses": list(self.alternative_hypotheses),
            "limitations": list(self.limitations),
            "recommended_next_action": self.recommended_next_action,
            "remediation_available": self.remediation_available,
            "human_review_required": self.human_review_required,
        }


_BASE_LIMITATIONS = [
    "Observation is not proof.",
    "Correlation is not causation.",
    "CONNECTION_REFUSED is not by itself proof of a firewall block, proxy interference, malware, or an attack.",
    "A closed port does not prove that a firewall blocked it.",
    "Do not label a process malicious solely because it listens on localhost.",
]


def _tier(label: str, enum: ProofTier) -> tuple[str, str]:
    return label, enum.value


def classify_localhost_failure(
    *,
    resolution_errors: list[str],
    tcp_probes: list[TcpProbeResult],
    listeners: ListenerDiscoveryResult,
    http_probes: list[HttpProbeResult],
    proxy: ProxyEvidence | None,
    nearby_count: int = 0,
    prior_listener_evidence: bool = False,
    access_denied: bool = False,
) -> ClassificationResult:
    """Map probe evidence to a primary classification without overclaiming.

    Applies a priority-ordered decision tree: each branch returns the first
    code whose evidence conditions are met.  All returned results include the
    shared ``_BASE_LIMITATIONS`` list to prevent downstream overconfidence.

    Args:
        resolution_errors: Non-empty when ``socket.getaddrinfo`` failed for
            the target host; used to short-circuit before TCP probing.
        tcp_probes: Ordered list from ``tcp_probe_many``; may be empty when
            resolution itself failed.
        listeners: Result of ``discover_listeners``; ``race_note`` triggers
            ``LOCALHOST_TRANSIENT_RACE`` when combined with refused probes.
        http_probes: May be empty; ``direct`` vs ``proxy_aware`` modes used
            to detect proxy interference only when both are present.
        proxy: ``ProxyEvidence`` from ``collect_proxy_evidence``; ``None``
            disables proxy-interference checks.
        nearby_count: Number of nearby loopback listeners discovered; a
            non-zero value weakly suggests a port change.
        prior_listener_evidence: When True, raises ``SERVICE_NOT_LISTENING``
            to ``PROCESS_EXITED_OR_RESTARTED`` under T4.
        access_denied: When True, returns ``LOCALHOST_ACCESS_DENIED`` before
            other checks; signals privilege gap rather than listener state.

    Returns:
        A ``ClassificationResult`` with ``code``, ``confidence``,
        ``proof_tier``, ``limitations``, and operator guidance.

    Audit note:
        This function is a critical path for every diagnose run.  The returned
        ``code`` and ``proof_tier`` are written to the audit JSONL by
        ``runner.py``.  Never add side effects here; keep it a pure mapping.
    """

    any_connected = any(p.connect_success for p in tcp_probes)
    refused = [p for p in tcp_probes if p.error_category == "CONNECTION_REFUSED"]
    timeouts = [p for p in tcp_probes if p.error_category == "TIMEOUT"]
    has_listener = bool(listeners.listeners)
    ipv4_ok = any(p.connect_success and p.address_family == "IPv4" for p in tcp_probes)
    ipv6_ok = any(p.connect_success and p.address_family == "IPv6" for p in tcp_probes)
    ipv4_refused = any(
        p.error_category == "CONNECTION_REFUSED" and p.address_family == "IPv4" for p in tcp_probes
    )
    ipv6_refused = any(
        p.error_category == "CONNECTION_REFUSED" and p.address_family == "IPv6" for p in tcp_probes
    )

    listener_scopes = {r.binding_scope for r in listeners.listeners}
    listener_families = {r.address_family for r in listeners.listeners}

    direct = next((h for h in http_probes if h.mode == "direct"), None)
    proxy_http = next((h for h in http_probes if h.mode == "proxy_aware"), None)

    if resolution_errors and not tcp_probes:
        t_label, t_enum = _tier("T1", ProofTier.T1_LOCAL_CONFIG_EVIDENCE)
        return ClassificationResult(
            code="LOCALHOST_NAME_RESOLUTION_ERROR",
            confidence=0.8,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["resolution"],
            limitations=list(_BASE_LIMITATIONS),
            recommended_next_action="Verify hosts-file and DNS resolution for localhost; retry with 127.0.0.1.",
            human_review_required=False,
        )

    if access_denied:
        t_label, t_enum = _tier("T1", ProofTier.T1_LOCAL_CONFIG_EVIDENCE)
        return ClassificationResult(
            code="LOCALHOST_ACCESS_DENIED",
            confidence=0.7,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["permission"],
            limitations=list(_BASE_LIMITATIONS),
            recommended_next_action="Re-run with sufficient privileges for process/listener inspection.",
            human_review_required=True,
        )

    if listeners.race_note and not has_listener and refused:
        t_label, t_enum = _tier("T3", ProofTier.T3_BEHAVIORAL_REPRODUCTION)
        return ClassificationResult(
            code="LOCALHOST_TRANSIENT_RACE",
            confidence=0.72,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["listeners.race_note", "tcp_probes"],
            limitations=list(_BASE_LIMITATIONS) + [listeners.race_note],
            recommended_next_action="Re-run diagnosis immediately; capture localhost-watch during reproduction.",
            human_review_required=True,
        )

    if has_listener and (
        (
            ipv4_ok
            and ipv6_refused
            and "IPv6" not in listener_families
            and "wildcard" not in listener_scopes
        )
        or (
            ipv6_ok
            and ipv4_refused
            and "IPv4" not in listener_families
            and "wildcard" not in listener_scopes
        )
    ):
        t_label, t_enum = _tier("T3", ProofTier.T3_BEHAVIORAL_REPRODUCTION)
        fam = "IPv4" if ipv4_ok else "IPv6"
        return ClassificationResult(
            code="LOCALHOST_IPV4_IPV6_BIND_MISMATCH",
            confidence=0.88,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["tcp_probes", "listeners"],
            alternative_hypotheses=["LOCALHOST_LISTENER_ACTIVE"],
            limitations=list(_BASE_LIMITATIONS),
            recommended_next_action=f"Retry using the address family that connects ({fam}).",
            remediation_available=True,
            human_review_required=False,
        )

    if (
        proxy
        and proxy.relation_to_incident == "possible_proxy_interference"
        and direct
        and proxy_http
    ):
        if direct.success and not proxy_http.success:
            t_label, t_enum = _tier("T3", ProofTier.T3_BEHAVIORAL_REPRODUCTION)
            return ClassificationResult(
                code="LOCALHOST_PROXY_INTERFERENCE",
                confidence=0.78,
                proof_tier=t_label,
                proof_tier_enum=t_enum,
                supporting_evidence_ids=["http_direct", "http_proxy_aware", "proxy_evidence"],
                alternative_hypotheses=["LOCALHOST_HTTP_APPLICATION_ERROR"],
                limitations=list(_BASE_LIMITATIONS)
                + ["Do not recommend proxy-disable merely because a localhost page failed."],
                recommended_next_action="Compare direct vs system-proxy paths; preview proxy remediation only if dead local proxy is corroborated.",
                remediation_available=True,
                human_review_required=True,
            )

    if any_connected and direct and direct.status_code is not None and direct.status_code >= 400:
        t_label, t_enum = _tier("T3", ProofTier.T3_BEHAVIORAL_REPRODUCTION)
        return ClassificationResult(
            code="LOCALHOST_HTTP_APPLICATION_ERROR",
            confidence=0.82,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["tcp_probes", "http_direct"],
            limitations=list(_BASE_LIMITATIONS),
            recommended_next_action="Inspect application logs for the listening process; TCP path is up.",
            remediation_available=True,
            human_review_required=False,
        )

    if any_connected and has_listener:
        t_label, t_enum = _tier("T3", ProofTier.T3_BEHAVIORAL_REPRODUCTION)
        return ClassificationResult(
            code="LOCALHOST_LISTENER_ACTIVE",
            confidence=0.9,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["tcp_probes", "listeners"],
            limitations=list(_BASE_LIMITATIONS),
            recommended_next_action="Listener is active; if the browser still fails, compare HTTP direct vs proxy-aware paths.",
            remediation_available=False,
            human_review_required=False,
        )

    if not has_listener and nearby_count > 0 and not any_connected:
        t_label, t_enum = _tier("T2", ProofTier.T2_RUNTIME_CORROBORATION)
        return ClassificationResult(
            code="LOCALHOST_PORT_CHANGED_POSSIBLE",
            confidence=0.55,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["listeners", "nearby_listeners"],
            contradicting_evidence_ids=[],
            alternative_hypotheses=["LOCALHOST_SERVICE_NOT_LISTENING"],
            limitations=list(_BASE_LIMITATIONS)
            + [
                "Nearby listeners are weak evidence; do not claim a replacement port without stronger proof."
            ],
            recommended_next_action="Compare nearby listener process identity; update the URL only if the same application owns the new port.",
            remediation_available=True,
            human_review_required=True,
        )

    if not has_listener and not any_connected and prior_listener_evidence:
        t_label, t_enum = _tier("T4", ProofTier.T4_OPERATOR_CONFIRMED)
        return ClassificationResult(
            code="LOCALHOST_PROCESS_EXITED_OR_RESTARTED",
            confidence=0.7,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["prior_listener_evidence", "tcp_probes", "listeners"],
            limitations=list(_BASE_LIMITATIONS),
            recommended_next_action="Reopen the application that previously hosted this localhost URL.",
            remediation_available=True,
            human_review_required=False,
        )

    if timeouts and not refused and not any_connected:
        t_label, t_enum = _tier("T1", ProofTier.T1_LOCAL_CONFIG_EVIDENCE)
        return ClassificationResult(
            code="LOCALHOST_TIMEOUT",
            confidence=0.75,
            proof_tier=t_label,
            proof_tier_enum=t_enum,
            supporting_evidence_ids=["tcp_probes"],
            alternative_hypotheses=["LOCALHOST_SERVICE_NOT_LISTENING"],
            limitations=list(_BASE_LIMITATIONS),
            recommended_next_action="Retry with a longer timeout; check whether the process is hung rather than absent.",
            human_review_required=True,
        )

    if not has_listener and not any_connected:
        # T2 when repeated refused probes + no listener
        tier_label = "T2" if len(refused) >= 2 or len(tcp_probes) >= 2 else "T1"
        enum = (
            ProofTier.T2_RUNTIME_CORROBORATION
            if tier_label == "T2"
            else ProofTier.T1_LOCAL_CONFIG_EVIDENCE
        )
        return ClassificationResult(
            code="LOCALHOST_SERVICE_NOT_LISTENING",
            confidence=0.92 if len(tcp_probes) >= 2 else 0.8,
            proof_tier=tier_label,
            proof_tier_enum=enum.value,
            supporting_evidence_ids=["tcp_probes", "listeners"],
            alternative_hypotheses=["LOCALHOST_PROCESS_EXITED_OR_RESTARTED"]
            if not prior_listener_evidence
            else [],
            limitations=list(_BASE_LIMITATIONS)
            + [
                "Without prior listener/timeline evidence, prefer LOCALHOST_SERVICE_NOT_LISTENING over PROCESS_EXITED.",
            ],
            recommended_next_action="Reopen the application that created this localhost page, then refresh the URL.",
            remediation_available=True,
            human_review_required=False,
        )

    t_label, t_enum = _tier("T0", ProofTier.T0_OBSERVATION_ONLY)
    return ClassificationResult(
        code="UNKNOWN_LOCALHOST_FAILURE",
        confidence=0.4,
        proof_tier=t_label,
        proof_tier_enum=t_enum,
        supporting_evidence_ids=[],
        limitations=list(_BASE_LIMITATIONS),
        recommended_next_action="Collect more evidence with --include-process --include-http --include-nearby-listeners.",
        human_review_required=True,
    )
