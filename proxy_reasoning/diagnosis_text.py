"""Conservative user-facing diagnosis from structured evidence only.

Module responsibility:
    Render short operator text from a ``ProxyReasoningRun`` without banned overclaim terms.

Output guarantees:
    Omits malware/hijack vocabulary unless proof-tier evidence is modeled upstream.

Side effects:
    None.
"""

from __future__ import annotations

from proxy_reasoning.constants import ATTRIBUTION_LIMITATION, MALWARE_CLAIM_FORBIDDEN
from proxy_reasoning.models import ProxyReasoningRun

_BANNED_TERMS = ("malware", "hijack", "attacker", "compromised", "evil")


def _safe_line(prefix: str, text: str) -> str:
    lower = text.lower()
    for term in _BANNED_TERMS:
        if term in lower and "not" not in lower[:20]:
            text = text.replace(term, "[redacted-unproven-term]")
    return f"{prefix}: {text}"


def render_proxy_diagnosis(run: ProxyReasoningRun) -> dict[str, str | list[str]]:
    """Render observed / inferred / unproven sections without overclaiming."""
    cfg = run.entity.configuration_attributes
    net = run.entity.network_attributes
    proc = run.entity.process_attribution_attributes
    trust = run.entity.trust_risk_attributes
    policy = run.policy_decision

    observed: list[str] = []
    if cfg.proxy_enable is not None:
        observed.append(
            f"WinINET proxy_enable={cfg.proxy_enable}"
            + (f", proxy_server={cfg.proxy_server!r}" if cfg.proxy_server else ""),
        )
    if cfg.wininet_winhttp_divergent:
        observed.append("WinINET and WinHTTP proxy configuration diverge.")
    if net.is_loopback and net.port:
        observed.append(f"Proxy target appears loopback on port {net.port}.")
    if proc.process_name:
        observed.append(
            f"Listener correlation: process={proc.process_name!r}"
            + (f", pid={proc.pid}" if proc.pid else ""),
        )

    inferred: list[str] = []
    if run.accepted_hypothesis:
        top = next((h for h in run.hypotheses if h.case_id == run.accepted_hypothesis), None)
        if top:
            inferred.append(top.title)
    inferred.append(f"Trust classification: {trust.classification} (risk {trust.risk_level}).")
    for line in trust.rationale[:3]:
        inferred.append(line)

    unproven: list[str] = [
        "Not proven: which process changed proxy registry values or whether intent was malicious.",
        ATTRIBUTION_LIMITATION,
        MALWARE_CLAIM_FORBIDDEN,
    ]
    for lim in run.limitations[:5]:
        if lim not in unproven:
            unproven.append(lim)

    verification_status = run.entity.evidence_attributes.verification_status
    next_steps = [
        "Recommended next step: run remediation preview and collect before/after validation.",
        f"Policy outcome for requested action: {policy.decision}.",
    ]
    if policy.decision == "PREVIEW":
        next_steps.append(
            "Keep mutations in preview until operator confirms and verification is satisfactory."
        )

    sections = {
        "observed": [_safe_line("Observed", line) for line in observed]
        or ["Observed: no proxy signals in this run."],
        "inferred": [_safe_line("Inferred", line) for line in inferred],
        "not_proven": [_safe_line("Not proven", line) for line in unproven],
        "verification_status": verification_status,
        "policy_outcome": policy.decision,
        "recommended_next_steps": next_steps,
    }

    short = (
        f"Proxy reasoning selected {run.accepted_hypothesis or 'no hypothesis'}. "
        f"Classification {trust.classification}; verification {verification_status}; policy {policy.decision}."
    )
    sections["short_diagnosis"] = short
    return sections
