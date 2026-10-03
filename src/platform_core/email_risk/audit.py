"""Structured, redacted audit evidence for email risk assessments.

Module responsibility:
    Build one audit record per assessment for SOC triage, incident response,
    internal audit, compliance review, and forensic reconstruction.

Key invariants:
    * No message content: records hold signal *names*, weights, categories,
      and sources — never evidence phrases, bodies, subjects, URLs, account
      numbers, credentials, or tokens.
    * Identifiers are always masked / hashed here, even when the analysis ran
      with ``show_identifiers=True``.
    * ``evidence_hash`` links the record to the full (redacted) result;
      ``record_hash`` is a SHA-256 over the canonical record so later edits
      are detectable. Chaining across records is the job of the platform
      custody log (``src.platform_core.audit``), not this function.
    * ``automated_actions_taken`` is always empty and ``urls_visited`` is 0.

Side effects:
    None. Callers decide where (and whether) to persist the record.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import EmailRiskResult
from .privacy import redact_free_text, stable_hash

AUDIT_SCHEMA_VERSION = "email_risk_audit.v1"


def _hashed_identifier(value: str) -> str:
    if not value or value.startswith("sha256:"):
        return value
    return stable_hash(value)


def build_audit_record(result: EmailRiskResult) -> dict[str, Any]:
    """Return a JSON-safe, content-free audit record for ``result``."""
    summary = result.message_summary
    record: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "event": "email_risk_assessed",
        "analysis_id": result.analysis_id,
        "timestamp": result.timestamp_utc,
        "source_type": result.source_type,
        "source_format": result.source_format,
        "risk_level": result.risk_level.value,
        "score": result.score,
        "confidence": result.confidence,
        "confidence_band": result.confidence_band,
        "attack_chain": result.attack_chain.value,
        "signals": [
            {
                "signal": e.signal,
                "category": e.category.value,
                "source": e.source.value,
                "weight": e.weight,
            }
            for e in result.evidence
        ],
        "correlation_rules": [
            {"rule_id": a.rule_id, "delta": a.delta, "signals": list(a.signals)}
            for a in result.adjustments
        ],
        "level_floor_rule": result.level_floor_rule,
        "website_risk_contribution": result.website_risk_contribution.model_dump(mode="json"),
        "policy_decision": result.policy.primary_decision.value,
        "policy_decisions": [d.value for d in result.policy.decisions],
        "matched_policies": [m.policy_id for m in result.policy.matched_policies],
        "recommended_actions": list(result.policy.recommended_actions),
        "verification_required": result.policy.verification.required,
        "limitations": list(result.limitations),
        "ruleset_version": result.ruleset_version,
        "classifier_version": result.classifier_version,
        "policy_version": result.policy.policy_version,
        "evidence_hash": result.evidence_hash,
        "sender": redact_free_text(str(summary.get("from") or ""), show_identifiers=False),
        "sender_relationship": result.sender_relationship,
        "message_id": _hashed_identifier(str(summary.get("message_id") or "")),
        "url_count": len(result.url_assessments),
        "qr_decoded_count": summary.get("qr_decoded_count", 0),
        "urls_visited": 0,
        "advisory_only": True,
        "automated_actions_taken": [],
    }
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    record["record_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return record


__all__ = ["AUDIT_SCHEMA_VERSION", "build_audit_record"]
