"""Policy-gated recovery-agent orchestration.

This module intentionally stops before execution. Existing remediation commands remain the
only place where Windows state may be changed, preserving typed-confirmation and audit rules.
"""

from __future__ import annotations

from typing import Protocol

from windows_network_toolkit.decision.decision_model import DecisionResult
from windows_network_toolkit.decision.policy_engine import PolicyOutcome, evaluate_policy

from .models import (
    AgentDiagnosis,
    AgentDisposition,
    AgentRunResult,
    AgentStage,
    RepairPlan,
    RepairStep,
)


class DiagnosisAgent(Protocol):
    """Replaceable reasoning boundary (deterministic baseline or future LLM adapter)."""

    def diagnose(self, decision: DecisionResult) -> AgentDiagnosis: ...


class DecisionDiagnosisAgent:
    """Deterministic baseline that converts an existing DecisionResult into agent context."""

    def diagnose(self, decision: DecisionResult) -> AgentDiagnosis:
        limitations: list[str] = []
        if decision.confidence < 0.7:
            limitations.append("Decision confidence is below the remediation threshold.")
        if not decision.evidence_refs:
            limitations.append("No explicit evidence references were attached to the decision.")
        limitations.append(
            "Classification is a hypothesis; policy permission is not proof of safety."
        )
        return AgentDiagnosis(
            incident_type=decision.incident_type,
            confidence=decision.confidence,
            hypothesis=decision.reasoning or decision.incident_type.value,
            evidence_refs=list(decision.evidence_refs),
            limitations=limitations,
            human_review_required=decision.human_review_required,
        )


class RepairPlannerAgent:
    """Build a bounded plan around the existing recommended action."""

    def plan(self, decision: DecisionResult, diagnosis: AgentDiagnosis) -> RepairPlan:
        action = decision.recommended_action or "OBSERVE_ONLY"
        mutates = action.startswith(("DISABLE", "STOP", "RESET", "FLUSH", "MODIFY"))
        steps = [
            RepairStep(action="CAPTURE_BEFORE_STATE", purpose="Preserve pre-change evidence."),
            RepairStep(
                action="REMEDIATION_PREVIEW", purpose=f"Preview candidate action: {action}."
            ),
        ]
        if action != "OBSERVE_ONLY":
            steps.append(
                RepairStep(
                    action=action,
                    purpose="Execute only through the existing policy-gated remediation path.",
                    mutates_state=mutates,
                    requires_confirmation=decision.requires_confirmation or mutates,
                    rollback=decision.rollback_plan,
                )
            )
        return RepairPlan(
            incident_id=decision.incident_id,
            diagnosis=diagnosis,
            steps=steps,
            verification_steps=[
                "RECOLLECT_NETWORK_STATE",
                "REPLAY_RELEVANT_CONNECTIVITY_PROBES",
                "COMPARE_BEFORE_AFTER_EVIDENCE",
                "CHECK_FOR_REGRESSION",
            ],
            retry_budget=1,
            stopping_conditions=[
                "policy blocks the candidate action",
                "human review is required",
                "verification detects regression",
                "retry budget is exhausted",
            ],
        )


class RecoveryAgentOrchestrator:
    """Coordinate diagnosis -> planning -> policy gate without autonomous mutation."""

    def __init__(self, diagnosis_agent: DiagnosisAgent | None = None) -> None:
        self._diagnosis_agent = diagnosis_agent or DecisionDiagnosisAgent()
        self._planner = RepairPlannerAgent()

    def run(
        self,
        decision: DecisionResult,
        *,
        dry_run: bool = True,
        has_admin: bool = False,
        evidence_level: str | None = None,
    ) -> AgentRunResult:
        diagnosis = self._diagnosis_agent.diagnose(decision)
        plan = self._planner.plan(decision, diagnosis)
        policy = evaluate_policy(
            decision,
            dry_run=dry_run,
            has_admin=has_admin,
            evidence_level=evidence_level,
        )

        outcome = policy["outcome"]
        mutable_without_rollback = next(
            (
                step
                for step in plan.steps
                if step.mutates_state and step.requires_confirmation and not step.rollback.strip()
            ),
            None,
        )
        if mutable_without_rollback is not None:
            outcome = PolicyOutcome.REQUIRE_ROLLBACK_PLAN.value
            policy["outcome"] = outcome
            policy["blocked_actions"] = sorted(
                set(policy.get("blocked_actions", [])) | {mutable_without_rollback.action}
            )
        if diagnosis.human_review_required or outcome == PolicyOutcome.HUMAN_REVIEW_REQUIRED.value:
            disposition = AgentDisposition.ESCALATE
            stage = AgentStage.ESCALATE
        elif outcome in {
            PolicyOutcome.BLOCK_UNSAFE_ACTION.value,
            PolicyOutcome.REQUIRE_ADMIN.value,
            PolicyOutcome.REQUIRE_ROLLBACK_PLAN.value,
        }:
            disposition = AgentDisposition.BLOCKED
            stage = AgentStage.STOP
        elif decision.requires_confirmation:
            disposition = AgentDisposition.AWAIT_CONFIRMATION
            stage = AgentStage.POLICY
        else:
            disposition = AgentDisposition.PREVIEW_READY
            stage = AgentStage.POLICY

        audit_events = [
            {
                "event": "agent_diagnosis",
                "incident_id": decision.incident_id,
                "decision_id": decision.decision_id,
                "incident_type": diagnosis.incident_type.value,
                "confidence": diagnosis.confidence,
            },
            {
                "event": "agent_policy_gate",
                "incident_id": decision.incident_id,
                "decision_id": decision.decision_id,
                "outcome": outcome,
                "dry_run": dry_run,
                "disposition": disposition.value,
            },
        ]

        return AgentRunResult(
            incident_id=decision.incident_id,
            decision_id=decision.decision_id,
            stage=stage,
            disposition=disposition,
            plan=plan,
            policy=policy,
            audit_events=audit_events,
        )
