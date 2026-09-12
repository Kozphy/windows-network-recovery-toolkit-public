"""Human review queue — persistent workflow for technology risk triage.

Module responsibility:
    Enforces the governance rule that accusatory-adjacent classifications
    (``UNKNOWN_LOCAL_PROXY``, ``SUSPICIOUS_PROXY``, ``POSSIBLE_MITM_RISK``,
    ``REVERTER_SUSPECTED``, etc.) must pass through human review before any remediation
    narrative is produced.  Provides ``HumanReviewItem`` / ``HumanReviewDecision``
    Pydantic models, a JSONL persistence helper, and queue-building utilities consumed by
    reporting and governance layers.

Typical usage:
    item = enqueue_from_incident(incident_id=..., classification="SUSPICIOUS_PROXY", ...)
    queue = items_needing_review(audit_records)

Limitations:
    - AI actors are rejected for risky approval actions; human actor identity is not
      cryptographically verified by this module.
    - Persistence is append-only JSONL; no deduplication across process restarts beyond
      the ``seen`` set inside ``items_needing_review``.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, model_validator

# Accusatory-adjacent classifications requiring human review before remediation narrative.
REVIEW_CLASSES = frozenset(
    {
        "UNKNOWN_LOCAL_PROXY",
        "SUSPICIOUS_PROXY",
        "SUSPICIOUS_LOCAL_PROXY",
        "POSSIBLE_MITM_RISK",
        "REVERTER_SUSPECTED",
    }
)

_RISKY_APPROVE_ACTIONS = frozenset(
    {
        "approve_remediation_preview",
        "override_classification",
    }
)

_AI_ACTOR_PREFIXES = ("ai_", "gpt", "claude", "copilot", "assistant", "model")


class HumanReviewStatus(StrEnum):
    """Represent the human review status enum.

    Variants:
        PENDING_REVIEW: Structured value carried by this enum.
        ACCEPTED: Structured value carried by this enum.
        OVERRIDDEN: Structured value carried by this enum.
        NEEDS_MORE_EVIDENCE: Structured value carried by this enum.
        REJECTED: Structured value carried by this enum.
        CLOSED: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    PENDING_REVIEW = "PENDING_REVIEW"
    ACCEPTED = "ACCEPTED"
    OVERRIDDEN = "OVERRIDDEN"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    REJECTED = "REJECTED"
    CLOSED = "CLOSED"


class ReviewAction(StrEnum):
    """Represent the review action enum.

    Variants:
        ACCEPT_CLASSIFICATION: Structured value carried by this enum.
        OVERRIDE_CLASSIFICATION: Structured value carried by this enum.
        REQUEST_MORE_EVIDENCE: Structured value carried by this enum.
        APPROVE_REMEDIATION_PREVIEW: Structured value carried by this enum.
        REJECT_REMEDIATION: Structured value carried by this enum.
        MARK_FALSE_POSITIVE: Structured value carried by this enum.
        CLOSE_NO_ACTION: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    ACCEPT_CLASSIFICATION = "accept_classification"
    OVERRIDE_CLASSIFICATION = "override_classification"
    REQUEST_MORE_EVIDENCE = "request_more_evidence"
    APPROVE_REMEDIATION_PREVIEW = "approve_remediation_preview"
    REJECT_REMEDIATION = "reject_remediation"
    MARK_FALSE_POSITIVE = "mark_false_positive"
    CLOSE_NO_ACTION = "close_no_action"


class HumanReviewItem(BaseModel):
    """Represent the human review item type.

    Key fields:
        review_id: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        evidence_id: Structured value carried by this type.
        classification: Structured value carried by this type.
        policy_decision_id: Structured value carried by this type.
        status: Structured value carried by this type.
        created_at: Structured value carried by this type.
        assigned_to: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    review_id: str
    incident_id: str
    evidence_id: str
    classification: str
    policy_decision_id: str = ""
    status: HumanReviewStatus = HumanReviewStatus.PENDING_REVIEW
    created_at: str = ""
    assigned_to: str | None = None
    reason: str = ""


class HumanReviewDecision(BaseModel):
    """Represent the human review decision type.

    Key fields:
        review_id: Structured value carried by this type.
        action: Structured value carried by this type.
        reason: Structured value carried by this type.
        actor: Structured value carried by this type.
        timestamp: Structured value carried by this type.
        evidence_id: Structured value carried by this type.
        policy_decision_id: Structured value carried by this type.
        override_classification: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    review_id: str
    action: ReviewAction
    reason: str
    actor: str
    timestamp: str = ""
    evidence_id: str = ""
    policy_decision_id: str = ""
    override_classification: str | None = None

    @model_validator(mode="after")
    def _require_reason(self) -> HumanReviewDecision:
        if not self.reason.strip():
            raise ValueError("reason is required for human review decisions")
        return self


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, separators=(",", ":")) + "\n")


def classification_needs_review(classification: str) -> bool:
    """Return classification needs review.

    Args:
        classification: classification supplied by the caller.

    Returns:
        The computed `bool` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return classification.upper() in REVIEW_CLASSES


def items_needing_review(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build human-review queue entries from audit records (report helper)."""
    from src.platform_core.risk.business_impact_mapping import map_business_impact

    queue: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in records:
        cls = ""
        if isinstance(row.get("classification"), dict):
            cls = str(row["classification"].get("primary_classification", "")).upper()
        else:
            cls = str(row.get("classification", "")).upper()
        if cls not in REVIEW_CLASSES:
            continue
        inc = str(row.get("incident_id") or row.get("case_id") or row.get("timestamp") or "")
        if inc in seen:
            continue
        seen.add(inc)
        queue.append(
            {
                "incident_id": row.get("incident_id") or row.get("case_id"),
                "classification": cls,
                "reason": "Accusatory-adjacent classification requires human review before remediation narrative.",
                "recommended_forum": map_business_impact(cls).suggested_forum,
            }
        )
    return queue


def enqueue_from_incident(
    *,
    incident_id: str,
    classification: str,
    evidence_id: str,
    policy_decision_id: str = "",
    assigned_to: str | None = None,
) -> HumanReviewItem | None:
    """Create a pending review item when classification requires human review."""
    if not classification_needs_review(classification):
        return None
    return HumanReviewItem(
        review_id=f"HR-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        evidence_id=evidence_id,
        classification=classification.upper(),
        policy_decision_id=policy_decision_id,
        status=HumanReviewStatus.PENDING_REVIEW,
        created_at=_utc_now(),
        assigned_to=assigned_to,
        reason="Accusatory-adjacent classification requires human review.",
    )


def _validate_decision_actor(decision: HumanReviewDecision) -> None:
    actor_lower = decision.actor.lower()
    if any(actor_lower.startswith(p) for p in _AI_ACTOR_PREFIXES):
        if decision.action in _RISKY_APPROVE_ACTIONS:
            raise ValueError("AI actors cannot approve remediation or override classifications")
    if decision.action in _RISKY_APPROVE_ACTIONS:
        if not decision.evidence_id.strip():
            raise ValueError("evidence_id required for risky review actions")
        if not decision.policy_decision_id.strip():
            raise ValueError("policy_decision_id required for risky review actions")


def record_decision(
    decision: HumanReviewDecision,
    *,
    audit_dir: Path,
) -> dict[str, Any]:
    """Append human review decision to human_review.jsonl and audit mirror."""
    _validate_decision_actor(decision)
    if not decision.timestamp:
        decision = decision.model_copy(update={"timestamp": _utc_now()})

    review_path = audit_dir / "human_review.jsonl"
    audit_path = audit_dir / "audit.jsonl"

    item_row = decision.model_dump()
    item_row["event"] = "human_review_decision"
    _append_jsonl(review_path, item_row)

    audit_row = {
        "timestamp": decision.timestamp,
        "incident_id": decision.review_id,
        "action": decision.action.value,
        "actor": decision.actor,
        "reason": decision.reason,
        "evidence_id": decision.evidence_id,
        "policy_decision_id": decision.policy_decision_id,
        "dry_run": True,
        "limitations": ["Human review decision — not autonomous remediation."],
    }
    _append_jsonl(audit_path, audit_row)

    return {"review_path": str(review_path), "audit_path": str(audit_path), "decision": item_row}


def list_pending(items_path: Path) -> list[HumanReviewItem]:
    """List pending.

    Args:
        items_path: items path supplied by the caller.

    Returns:
        The computed `list[HumanReviewItem]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    if not items_path.is_file():
        return []
    items: list[HumanReviewItem] = []
    for line in items_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("status") == HumanReviewStatus.PENDING_REVIEW.value:
            items.append(HumanReviewItem.model_validate(row))
    return items


def get_item(review_id: str, items_path: Path) -> HumanReviewItem | None:
    """Get item.

    Args:
        review_id: review id supplied by the caller.
        items_path: items path supplied by the caller.

    Returns:
        The computed `HumanReviewItem | None` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    if not items_path.is_file():
        return None
    for line in items_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("review_id") == review_id:
            return HumanReviewItem.model_validate(row)
    return None
