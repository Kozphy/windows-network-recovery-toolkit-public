"""Reporting Service — governance and executive reports."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from backend.db.models import ControlTestResult, HumanReviewItem, PlatformDecisionRecord
from backend.services.base import TenantContext
from src.platform_core.governance.audit_report import build_audit_governance_report
from windows_network_toolkit.analytics_pipeline import run_endpoint_analytics_pipeline
from windows_network_toolkit.reporting import build_executive_report


class ReportingService:
    """Represent reporting service data used by the toolkit.
    
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

    def governance_report(self, *, audit_dir: Path | None = None) -> dict[str, Any]:
        """Governance report.
        
        Args:
            audit_dir: The audit dir value supplied by the caller.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        path = audit_dir or Path(
            os.getenv("PLATFORM_DATA_DIR", "tests/fixtures/risk_analytics/audit_sample")
        )
        if (path / "incidents.jsonl").is_file():
            raw = build_audit_governance_report(path, format="json")
            return raw if isinstance(raw, dict) else {"report": raw}
        return {
            "schema_version": "audit_governance_report.v2",
            "tenant_id": self._ctx.tenant_id,
            "limitations": ["No audit directory — committee report unavailable."],
        }

    def executive_summary(self, *, fixture: dict[str, Any] | None = None) -> dict[str, Any]:
        """Executive summary.
        
        Args:
            fixture: The fixture value supplied by the caller.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        if fixture:
            payload = run_endpoint_analytics_pipeline(fixture=fixture)
        else:
            payload = {"incidents": [], "control_tests": [], "limitations": []}
        report = build_executive_report(payload)
        report["tenant_id"] = self._ctx.tenant_id
        return report

    def decision_dashboard(self) -> dict[str, Any]:
        """Decision dashboard.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        
        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        decisions = list(
            self._session.exec(
                select(PlatformDecisionRecord)
                .where(PlatformDecisionRecord.tenant_id == self._ctx.tenant_id)
                .order_by(PlatformDecisionRecord.created_at.desc())
                .limit(100)
            ).all()
        )
        pending_reviews = list(
            self._session.exec(
                select(HumanReviewItem).where(HumanReviewItem.status == "PENDING_REVIEW").limit(50)
            ).all()
        )
        controls = list(
            self._session.exec(select(ControlTestResult).limit(100)).all()
        )
        return {
            "tenant_id": self._ctx.tenant_id,
            "decision_count": len(decisions),
            "pending_human_reviews": len(pending_reviews),
            "control_test_count": len(controls),
            "recent_decisions": [
                {
                    "decision_id": d.decision_id,
                    "policy_outcome": d.policy_outcome,
                    "confidence_label": d.confidence_label,
                    "human_approval_status": d.human_approval_status,
                }
                for d in decisions[:20]
            ],
            "limitations": [
                "Management information — not formal audit opinion.",
                "Not antivirus, EDR, or autonomous remediation.",
            ],
        }
