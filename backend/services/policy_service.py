"""Policy Engine Service — YAML policy packs + canonical evaluate_policy."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, select

from backend.db.models import PolicyPackRecord
from backend.services.base import TenantContext, ensure_tenant
from backend.services.policy_yaml import evaluate_yaml_policy, load_policy_yaml
from src.platform_core.contracts import Decision, EvidenceBundle
from src.platform_core.evidence.tiers import EvidenceTier
from src.platform_core.policy.engine import evaluate_policy


class PolicyService:
    """Represent policy service data used by the toolkit.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    def __init__(self, session: Session, ctx: TenantContext) -> None:
        """Initialize the object with caller supplied state.
        
        Args:
            session: Database session used to read or persist records.
            ctx: The ctx value supplied by the caller.
        
        Returns:
            None.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        self._session = session
        self._ctx = ctx
        ensure_tenant(session, ctx.tenant_id)

    def get_active_policy_doc(self) -> dict[str, Any]:
        """Get active policy doc.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        
        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        row = self._session.exec(
            select(PolicyPackRecord)
            .where(
                PolicyPackRecord.tenant_id == self._ctx.tenant_id,
                PolicyPackRecord.active == True,  # noqa: E712
            )
            .order_by(PolicyPackRecord.created_at.desc())
        ).first()
        if row:
            import yaml

            return yaml.safe_load(row.yaml_content) or {}
        return load_policy_yaml()

    def register_policy_pack(self, *, yaml_content: str, version: str = "1.0.0", activate: bool = True) -> PolicyPackRecord:
        """Register policy pack.
        
        Args:
            yaml_content: The yaml content value supplied by the caller.
            version: The version value supplied by the caller.
            activate: The activate value supplied by the caller.
        
        Returns:
            The PolicyPackRecord result produced by the operation.
        
        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        
        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        if activate:
            for existing in self._session.exec(
                select(PolicyPackRecord).where(PolicyPackRecord.tenant_id == self._ctx.tenant_id)
            ).all():
                existing.active = False
                self._session.add(existing)
        pack_id = f"pol-{uuid.uuid4().hex[:12]}"
        row = PolicyPackRecord(
            pack_id=pack_id,
            tenant_id=self._ctx.tenant_id,
            version=version,
            yaml_content=yaml_content,
            active=activate,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def evaluate(
        self,
        *,
        classification: str,
        confidence_score: float,
        evidence_tier: str = "T1_STATE_EVIDENCE",
        requested_action: str = "observe",
        requires_human_review: bool = False,
        decision_id: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate.
        
        Args:
            classification: The classification value supplied by the caller.
            confidence_score: The confidence score value supplied by the caller.
            evidence_tier: The evidence tier value supplied by the caller.
            requested_action: The requested action value supplied by the caller.
            requires_human_review: The requires human review value supplied by the caller.
            decision_id: The decision id value supplied by the caller.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        yaml_eval = evaluate_yaml_policy(
            classification,
            policy_doc=self.get_active_policy_doc(),
            requested_action=requested_action,
        )

        dec_id = decision_id or f"dec-{uuid.uuid4().hex[:12]}"
        tier_map: dict[str, str] = {
            "T0_OBSERVATION_ONLY": "OBSERVED_ONLY",
            "T1_STATE_EVIDENCE": "CORRELATED",
            "T1_LOCAL_CONFIG_EVIDENCE": "CORRELATED",
            "T2_RUNTIME_CORROBORATION": "PROVEN_REGISTRY_WRITER",
            "T3_BEHAVIORAL_REPRODUCTION": "PROVEN_NETWORK_IMPACT",
            "T4_OPERATOR_CONFIRMED": "FINAL_CAUSATION",
        }
        tier_name = tier_map.get(evidence_tier.upper(), "OBSERVED_ONLY")
        tier: EvidenceTier = tier_name  # type: ignore[assignment]

        from datetime import UTC, datetime

        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        decision = Decision(
            decision_id=dec_id,
            incident_id=dec_id,
            timestamp_utc=ts,
            incident_type=classification,
            recommended_action=requested_action,
            confidence=confidence_score,
            requires_human_review=requires_human_review or yaml_eval.requires_human_approval,
        )
        bundle = EvidenceBundle(
            bundle_id=f"bundle-{dec_id}",
            incident_id=dec_id,
            created_at=ts,
            tier=tier,
            items=[],
        )
        canonical = evaluate_policy(
            decision=decision,
            bundle=bundle,
            requested_action=requested_action,
            dry_run=True,
        )

        if requested_action in yaml_eval.blocked_actions:
            outcome = "BLOCK"
        elif yaml_eval.requires_human_approval:
            outcome = "REQUIRE_HUMAN_APPROVAL"
        else:
            outcome = canonical.outcome

        return {
            "classification": classification,
            "yaml_decision": yaml_eval.decision,
            "yaml_severity": yaml_eval.severity,
            "policy_outcome": outcome,
            "allowed_actions": list(yaml_eval.allowed_actions),
            "blocked_actions": list(yaml_eval.blocked_actions),
            "requires_human_approval": yaml_eval.requires_human_approval,
            "canonical_evaluation": canonical.model_dump(mode="json"),
            "limitations": list(yaml_eval.limitations),
            "rationale": canonical.rationale,
        }
