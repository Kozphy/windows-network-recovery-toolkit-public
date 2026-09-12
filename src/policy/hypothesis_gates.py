"""Map ranked hypotheses plus proof/trust signals to operator-facing remediation gates.

Purpose:
    Consume deterministic hypothesis scores (:mod:`src.hypothesis`), optional causal proof artefacts
    (:mod:`src.proof`), and trust aggregates (:mod:`src.observation`) to emit ALLOW / PREVIEW / BLOCK rows
    suitable for diagnose-live JSON payloads and audits.

Decision intent:
    ALLOW indicates safe-tier previews may proceed only after downstream confirmation—it never authorizes silent
    destructive remediation. Confidence bands gate unproven hypotheses; degraded trust caps ALLOW downward.

Inputs:
    Ordered ``(hypothesis_key, confidence, evidence_tuple)``, optional ``ProofResult``, proof enable flag,
    optional ``TrustAssessment`` for degraded-mode previews.

Outputs:
    JSON-serializable dict rows with hypotheses, rationale ``why`` strings, normalized ``risk_score`` fields.

Constraints:
    Confidence values are heuristic weights—not calibrated Bayesian posteriors. Proof scope today covers localhost
    proxy HTTPS contrasts for a fixed hypothesis subset; unrelated hypotheses remain UNPROVEN.

Known failure modes:
    Missing proofs leave ``proof_status=UNPROVEN``; contradictory trust signals force PREVIEW overrides even on
    CONFIRMED causal rows.

Verification / auditing:
    Diff ``hypothesis_decisions`` arrays against rerun ``replay`` output; inspect embedded ``why`` bullets for stale
    policy version mismatches.

Engineering Notes:
    Keeps string Enum policy decisions stable for dashboards and downstream allowlists relying on literals.

Boundary:
    Implements policy only—no subprocess or filesystem side effects inside this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from platform_core import policy_v2 as pv2

from ..hypothesis.keys import HypothesisKey
from ..hypothesis.risk import hypothesis_risk_score
from ..observation.trust import TrustAssessment
from ..proof.contracts import ProofResult, ProofStatus

# Confidence bands for *unproven* / inconclusive hypotheses (proof not CONFIRMED).
_HIGH_CONF_PREVIEW: Final[float] = 0.60
_LOW_CONF_BLOCK: Final[float] = 0.35


class PolicyDecision(StrEnum):
    """Operator-facing gate for remediation aligned to platform preview/execute split."""

    ALLOW = "ALLOW"
    """Causal proof confirmed; safe-tier fixes are policy-appropriate (still confirm at execute boundary)."""

    PREVIEW = "PREVIEW"
    """High-confidence diagnostic only, or uncertain band — previews and explicit confirmation required."""

    BLOCK = "BLOCK"
    """Low confidence, or proof rejected this causal story for the checked path — no remediation on this row."""


PROOF_LOCALHOST_PROXY_HYPOTHESES: frozenset[HypothesisKey] = frozenset(
    {
        "unexpected_user_proxy",
        "local_proxy_hijack",
        "browser_proxy_path_issue",
        "localhost_proxy_owner_suspicious",
        "winhttp_proxy_issue",
    }
)

HYPOTHESIS_DISPLAY_NAME: dict[HypothesisKey, str] = {
    "unexpected_user_proxy": "User proxy points at localhost while transport looks healthy",
    "local_proxy_hijack": "Loopback proxy active with attributed listener (possible intercept path)",
    "browser_proxy_path_issue": "Browser/proxy stack mismatch (curl vs WinINET/WinHTTP)",
    "localhost_proxy_owner_suspicious": "Local proxy owner process has limited trust signals",
    "socket_exhaustion": "Elevated TIME_WAIT/ESTABLISHED socket churn",
    "dns_resolution_issue": "DNS resolution failure pattern",
    "tls_path_issue": "TLS/certificate path suspicion",
    "winhttp_proxy_issue": "WinHTTP non-direct proxy with HTTPS probe failure",
    "winsock_corruption_possible": "Multiple layers failing — possible Winsock/stack issue",
    "isp_router_path_issue": "Gateway or ISP/upstream reachability pattern",
}


def hypothesis_display_name(key: HypothesisKey) -> str:
    """Stable human label for ``key`` in JSON payloads."""
    return HYPOTHESIS_DISPLAY_NAME.get(key, key.replace("_", " ").title())


def proof_status_token(
    *,
    hypothesis: HypothesisKey,
    localhost_proxy_proof: ProofResult | None,
    proofs_enabled: bool,
) -> str:
    """PUBLIC proof label: CONFIRMED | REJECTED | INCONCLUSIVE | UNPROVEN."""
    if not proofs_enabled:
        return "UNPROVEN"
    if hypothesis not in PROOF_LOCALHOST_PROXY_HYPOTHESES:
        return "UNPROVEN"
    if localhost_proxy_proof is None:
        return "UNPROVEN"
    # StrEnum / str subclass: `.name` is CONFIRMED, REJECTED, INCONCLUSIVE
    return localhost_proxy_proof.status.name


def decide_policy(
    *,
    confidence: float,
    proof_status: str,
) -> PolicyDecision:
    """Map confidence + proof outcome to ALLOW / PREVIEW / BLOCK."""
    return hypothesis_policy_detail(confidence=confidence, proof_status=proof_status)[0]


def hypothesis_policy_detail(
    *,
    confidence: float,
    proof_status: str,
) -> tuple[PolicyDecision, list[str], list[str]]:
    """Map confidence + proof to tri-state decision, v2 reason codes, and blocked actions."""
    reason_codes: list[str] = []
    blocked = list(pv2.ALWAYS_BLOCKED_ACTIONS)

    if proof_status == ProofStatus.CONFIRMED.name:
        reason_codes.extend([pv2.CONFIRMED_SAFE_TIER_WITH_CONFIRMATION, pv2.SAFE_TIER_ACTION])
        return PolicyDecision.ALLOW, reason_codes, blocked

    if proof_status == ProofStatus.REJECTED.name:
        reason_codes.append(pv2.PROOF_REJECTED_FOR_HYPOTHESIS)
        return PolicyDecision.BLOCK, reason_codes, blocked

    if proof_status == ProofStatus.INCONCLUSIVE.name:
        if confidence >= _HIGH_CONF_PREVIEW:
            reason_codes.extend([pv2.HIGH_CONFIDENCE_UNPROVEN, pv2.REQUIRES_OPERATOR_CONFIRMATION])
            return PolicyDecision.PREVIEW, reason_codes, blocked
        if confidence < _LOW_CONF_BLOCK:
            reason_codes.append(pv2.LOW_CONFIDENCE_BLOCK)
            return PolicyDecision.BLOCK, reason_codes, blocked
        reason_codes.append(pv2.REQUIRES_OPERATOR_CONFIRMATION)
        return PolicyDecision.PREVIEW, reason_codes, blocked

    if confidence >= _HIGH_CONF_PREVIEW:
        reason_codes.extend([pv2.HIGH_CONFIDENCE_UNPROVEN, pv2.REQUIRES_OPERATOR_CONFIRMATION])
        return PolicyDecision.PREVIEW, reason_codes, blocked
    if confidence < _LOW_CONF_BLOCK:
        reason_codes.append(pv2.LOW_CONFIDENCE_BLOCK)
        return PolicyDecision.BLOCK, reason_codes, blocked
    reason_codes.append(pv2.REQUIRES_OPERATOR_CONFIRMATION)
    return PolicyDecision.PREVIEW, reason_codes, blocked


def build_why(
    *,
    decision: PolicyDecision,
    confidence: float,
    proof_status: str,
    evidence: list[str],
    proof_summary: str | None,
    trust_notes: tuple[str, ...] = (),
    risk_score: float | None = None,
) -> list[str]:
    """Human-readable rationale list for JSON export."""
    why: list[str] = [
        f"confidence={confidence:.2f} (bands: low<{ _LOW_CONF_BLOCK }, high≥{ _HIGH_CONF_PREVIEW } when unproven).",
        f"proof_status={proof_status}.",
    ]
    if risk_score is not None:
        why.append(f"risk_score≈confidence×impact={risk_score:.4f}")
    why.extend(f"evidence: {line}" for line in evidence[:6])
    if proof_summary:
        why.append(f"proof_summary: {proof_summary}")
    why.extend(trust_notes)

    if decision == PolicyDecision.ALLOW:
        why.append(
            "Policy: causal proof CONFIRMED — safe-tier remediation may be executed only after explicit "
            "operator confirmation; destructive/high-risk actions stay blocked from auto-run."
        )
    elif decision == PolicyDecision.PREVIEW:
        why.append(
            "Policy: unproven or inconclusive causal proof — previews only; require typed confirmation "
            "before any state change."
        )
    else:
        why.append(
            "Policy: low confidence or causal proof REJECTED for this hypothesis — "
            "no remediation on this row (re-diagnose or gather more evidence)."
        )
    return why


@dataclass(frozen=True)
class HypothesisDecisionRow:
    """One row matching the decision-system JSON contract."""

    hypothesis_key: HypothesisKey
    hypothesis: str
    confidence: float
    proof_status: str
    why: tuple[str, ...]
    decision: PolicyDecision
    risk_score: float = 0.0

    reason_codes: tuple[str, ...] = ()
    blocked_actions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Keys: hypothesis, confidence, proof_status, why, decision (consumer contract)."""
        row = {
            "hypothesis": self.hypothesis,
            "confidence": round(self.confidence, 2),
            "proof_status": self.proof_status,
            "why": list(self.why),
            "decision": self.decision.value,
            "risk_score": round(self.risk_score, 4),
        }
        if self.reason_codes:
            row["reason_codes"] = list(self.reason_codes)
        if self.blocked_actions:
            row["blocked_actions"] = list(self.blocked_actions)
        return row


def build_hypothesis_decisions(
    *,
    ranked: list[tuple[HypothesisKey, float, tuple[str, ...]]],
    localhost_proxy_proof: ProofResult | None,
    proofs_enabled: bool,
    trust_assessment: TrustAssessment | None = None,
) -> list[dict[str, Any]]:
    """Produce ``hypothesis_decisions`` list for diagnose-live payloads.

    Args:
        ranked: Ordered ``(hypothesis_key, confidence, evidence_tuple)`` from live scoring.
        localhost_proxy_proof: Result of ``run_localhost_proxy_https_proof`` when ``proofs_enabled``.
        proofs_enabled: When False, all ``proof_status`` values are UNPROVEN.
        trust_assessment: When ``degraded_mode``, CONFIRMED ``ALLOW`` is capped to ``PREVIEW``.
    """
    rows: list[dict[str, Any]] = []
    proof_summary = localhost_proxy_proof.summary if localhost_proxy_proof else None

    cap_allow = trust_assessment is not None and trust_assessment.degraded_mode

    for key, conf, evid in ranked:
        pstat = proof_status_token(
            hypothesis=key,
            localhost_proxy_proof=localhost_proxy_proof,
            proofs_enabled=proofs_enabled,
        )
        dec, reason_codes, blocked_actions = hypothesis_policy_detail(
            confidence=float(conf),
            proof_status=pstat,
        )
        rscore = hypothesis_risk_score(float(conf), key)
        degraded_notes: list[str] = []
        if cap_allow and dec == PolicyDecision.ALLOW:
            dec = PolicyDecision.PREVIEW
            reason_codes = list(reason_codes) + [pv2.TRUST_DEGRADED_CAP_TO_PREVIEW]
            degraded_notes.append(
                "Degraded uncertainty: causal ALLOW capped to PREVIEW "
                "(low trust aggregate, conflicting signals, or proof-layer degradation)."
            )
        why_list = build_why(
            decision=dec,
            confidence=float(conf),
            proof_status=pstat,
            evidence=list(evid),
            proof_summary=proof_summary if key in PROOF_LOCALHOST_PROXY_HYPOTHESES else None,
            trust_notes=tuple(degraded_notes),
            risk_score=rscore,
        )
        rows.append(
            HypothesisDecisionRow(
                hypothesis_key=key,
                hypothesis=hypothesis_display_name(key),
                confidence=float(conf),
                proof_status=pstat,
                why=tuple(why_list),
                decision=dec,
                risk_score=rscore,
                reason_codes=tuple(reason_codes),
                blocked_actions=tuple(blocked_actions),
            ).to_dict(),
        )

    return rows
