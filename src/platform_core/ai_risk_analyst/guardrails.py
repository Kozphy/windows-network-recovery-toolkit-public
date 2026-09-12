"""Guardrails for AI risk recommendations — downgrade or refuse overreach.

Module responsibility:
    Applies deterministic post-processing to ``AIRecommendation`` objects produced by the
    AI risk analyst before they reach operators.  Rules include: downgrading confidence
    when evidence is incomplete, removing destructive action language, capping risk level
    for known development-tool proxy patterns, and escalating ``human_review`` status when
    two or more guardrail conditions are triggered.  Does not modify classification labels
    or emit audit events; it returns a corrected ``AIRecommendation`` only.

Typical usage:
    safe = apply_guardrails(recommendation, bundle)

Limitations:
    - Dev-tool detection is heuristic (process-name substring match); false negatives are
      possible for renamed or wrapped executables.
    - Guardrail rules are evaluated in a fixed order; interactions between rules are
      intentional but undocumented combinations may produce unexpected ``review_status``.
"""

from __future__ import annotations

from typing import Literal

from .models import AIRecommendation, AnalystEvidenceBundle, HumanReviewRequired, RiskLevel

ReviewStatus = Literal["not_required", "recommended", "required"]

_KNOWN_DEV_PROCESS_HINTS = frozenset(
    {"node.exe", "node", "cursor.exe", "code.exe", "vscode.exe", "wsl.exe"}
)

_SUSPICIOUS_CLASSIFICATIONS = frozenset(
    {
        "SUSPICIOUS_LOCAL_PROXY",
        "UNKNOWN_LOCAL_PROXY",
        "POSSIBLE_MITM_RISK",
        "REVERTER_SUSPECTED",
    }
)


def _classification_primary(bundle: AnalystEvidenceBundle) -> str:
    if bundle.classification:
        return str(bundle.classification.get("primary_classification", "")).upper()
    if bundle.proxy_status:
        return str(bundle.proxy_status.get("classification", "")).upper()
    return ""


def _listener_verified(bundle: AnalystEvidenceBundle) -> bool:
    if not bundle.listener_info:
        return False
    return bool(bundle.listener_info.get("listener_found"))


def _process_owner_known(bundle: AnalystEvidenceBundle) -> bool:
    proc = (bundle.listener_info or {}).get("process")
    if isinstance(proc, dict) and proc.get("name"):
        return True
    if isinstance(proc, str) and proc.strip():
        return True
    return False


def _registry_writer_proven(bundle: AnalystEvidenceBundle) -> bool:
    for entry in bundle.audit_log_entries:
        tier = str(entry.get("attribution_tier", entry.get("tier", ""))).upper()
        if tier in {"PROVEN_REGISTRY_WRITER", "FINAL_CAUSATION"}:
            return True
    writer = (bundle.proxy_status or {}).get("writer_attribution") or {}
    tier = str(writer.get("attribution_tier", writer.get("tier", ""))).upper()
    return tier in {"PROVEN_REGISTRY_WRITER", "FINAL_CAUSATION"}


def _tls_proof_present(bundle: AnalystEvidenceBundle) -> bool:
    if not bundle.tls_proof:
        return False
    status = str(bundle.tls_proof.get("status", bundle.tls_proof.get("conclusion", ""))).lower()
    return status in {"supported", "completed", "ok", "passed"}


def _is_known_dev_proxy(bundle: AnalystEvidenceBundle) -> bool:
    proc = (bundle.listener_info or {}).get("process") or {}
    name = str(proc.get("name", proc) if isinstance(proc, dict) else proc).lower()
    return any(hint in name for hint in _KNOWN_DEV_PROCESS_HINTS)


def apply_guardrails(
    recommendation: AIRecommendation,
    bundle: AnalystEvidenceBundle,
) -> AIRecommendation:
    """Downgrade recommendations when evidence is incomplete or actions are unsafe."""
    primary = _classification_primary(bundle)
    missing = list(recommendation.missing_evidence)
    review_reasons: list[str] = []
    checklist: list[str] = []
    risk_level: RiskLevel = recommendation.risk_level
    confidence = recommendation.confidence_level
    action = recommendation.recommended_action
    uncertainty = recommendation.uncertainty
    governance_notes = list(recommendation.governance_notes)

    if not bundle.proxy_status and not bundle.classification:
        missing.append("proxy_status_or_classification")
        review_reasons.append("No proxy status or classification evidence supplied.")
        confidence = "very_low"
        action = "Collect proxy-status and listener evidence before remediation preview."

    if primary in _SUSPICIOUS_CLASSIFICATIONS and not _listener_verified(bundle):
        missing.append("verified_localhost_listener")
        review_reasons.append("Suspicious classification without verified listener.")
        confidence = "low" if confidence == "high" else confidence
        action = "Continue read-only investigation; do not disable or kill processes automatically."

    if primary == "POSSIBLE_MITM_RISK" and not _tls_proof_present(bundle):
        missing.append("tls_proof")
        review_reasons.append("MITM-related classification requires TLS proof before escalation.")
        risk_level = "medium" if risk_level == "critical" else risk_level
        action = "Run tls-proof and compare direct vs proxied certificate paths (read-only)."

    if primary in {"UNKNOWN_LOCAL_PROXY", "REVERTER_SUSPECTED"} and not _registry_writer_proven(
        bundle
    ):
        missing.append("proven_registry_writer")
        review_reasons.append("Registry writer is not proven; attribution remains correlational.")
        confidence = "low"
        action = "Run proxy-writer-attribution or Sysmon correlation before any remediation."

    if bundle.listener_info and not _process_owner_known(bundle):
        missing.append("process_owner")
        review_reasons.append("Listener or proxy port owner is unknown.")
        checklist.append("Identify process owning localhost proxy port (read-only).")

    if _is_known_dev_proxy(bundle):
        governance_notes.append(
            "Known development-tool proxy pattern detected; not classified as malicious."
        )
        if risk_level in {"high", "critical"}:
            risk_level = "medium"
        review_reasons.append("Dev-tool proxy — confirm with owner before changes.")

    if any(
        phrase in action.lower()
        for phrase in ("kill", "disable proxy", "reset firewall", "modify registry")
    ):
        action = "Preview remediation only; require typed human confirmation and policy approval."
        review_reasons.append("Destructive action language removed by guardrails.")

    review_status: ReviewStatus = "not_required"
    if review_reasons:
        review_status = (
            "required"
            if len(review_reasons) >= 2 or primary in _SUSPICIOUS_CLASSIFICATIONS
            else "recommended"
        )

    human_review = HumanReviewRequired(
        required=review_status == "required",
        status=review_status,
        reasons=review_reasons,
        checklist=checklist
        or [
            "Confirm evidence tier and limitations with security reviewer.",
            "Verify policy outcome is PREVIEW_ONLY or REQUIRE_HUMAN_APPROVAL.",
            "Do not execute destructive actions from AI output.",
        ],
    )

    if missing:
        uncertainty = (
            uncertainty
            or "Evidence gaps remain; recommendations are advisory and may change with new proof."
        )

    return recommendation.model_copy(
        update={
            "missing_evidence": sorted(set(missing)),
            "risk_level": risk_level,
            "confidence_level": confidence,
            "recommended_action": action,
            "uncertainty": uncertainty,
            "human_review": human_review,
            "human_review_notes": "; ".join(review_reasons)
            if review_reasons
            else recommendation.human_review_notes,
            "governance_notes": governance_notes,
            "forbidden_actions": list(recommendation.forbidden_actions),
        }
    )


def recommendation_passes_safety(recommendation: AIRecommendation) -> bool:
    """Return False if recommendation text attempts forbidden execution."""
    text = f"{recommendation.recommended_action} {recommendation.likely_hypothesis}".lower()
    forbidden_phrases = (
        "execute automatically",
        "kill process now",
        "disable proxy now",
        "reset firewall",
        "modify registry without",
    )
    return not any(p in text for p in forbidden_phrases)


_ALLOWED_EXECUTION_AUTHORITY = frozenset({"preview_only", "human_required", "blocked"})


def enforce_advisory_only(payload: dict) -> dict:
    """Strip or downgrade AI fields that attempt to grant execution authority."""
    out = dict(payload)
    authority = str(out.get("execution_authority", "preview_only")).lower()
    if authority not in _ALLOWED_EXECUTION_AUTHORITY:
        out["execution_authority"] = "human_required"
    narrative = str(out.get("narrative", out.get("summary", "")))
    if any(
        p in narrative.lower() for p in ("execute automatically", "safe to execute", "full_auto")
    ):
        out["narrative"] = "Preview remediation only; human confirmation required."
        out["summary"] = out.get("summary", out["narrative"])
    if "automated" in authority or "auto" in authority:
        out["execution_authority"] = "human_required"
    return out
