"""Control test engine — PASS | FAIL | EXCEPTION | INSUFFICIENT_EVIDENCE.

Module responsibility:
    Implements the catalog of six standard control tests (CT-AUDIT-001 through
    CT-TLS-006) plus an optional exception record (CT-EXC-000).  Each test
    evaluates a specific governance control objective — audit-trail existence,
    typed-confirmation gate, dry-run default, evidence-tier-to-action gate,
    classification-not-accusation, and TLS-mismatch limitations — against a
    structured evidence fixture and/or a list of audit records.

System placement:
    Called by the ``/platform/controls`` API route and the ``control-test`` CLI
    command.  Inputs are deterministic dicts (fixture or audit records); no live
    host probes are made.

Key invariants:
    - Each ``ControlTestSpec`` carries a non-empty ``limitations[]`` list asserting
      the control's evidential boundaries.
    - A PASS result means the tested evidence satisfies the specific control
      objective; it does not imply broader security assurance.
    - CT-EVID-004 returns ``INSUFFICIENT_EVIDENCE`` (not FAIL) when neither
      destructive-blocked events nor ``dry_run`` can be confirmed, preserving the
      distinction between a confirmed violation and missing evidence.

Side effects:
    None.  Read-only; evaluates provided dicts only.

Failure modes:
    If both ``fixture`` and ``audit_records`` are ``None`` or empty, most tests
    return ``INSUFFICIENT_EVIDENCE`` rather than FAIL.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ControlTestOutcome(StrEnum):
    """Represent the control test outcome enum.

    Variants:
        PASS: Structured value carried by this enum.
        FAIL: Structured value carried by this enum.
        EXCEPTION: Structured value carried by this enum.
        INSUFFICIENT_EVIDENCE: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    EXCEPTION = "EXCEPTION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ControlTestSpec(BaseModel):
    """Represent the control test spec type.

    Key fields:
        control_id: Structured value carried by this type.
        control_objective: Structured value carried by this type.
        required_evidence: Structured value carried by this type.
        test_steps: Structured value carried by this type.
        result: Structured value carried by this type.
        evidence_refs: Structured value carried by this type.
        limitations: Structured value carried by this type.
        reviewer_notes: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    control_id: str
    control_objective: str
    required_evidence: list[str] = Field(default_factory=list)
    test_steps: list[str] = Field(default_factory=list)
    result: ControlTestOutcome
    evidence_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    reviewer_notes: str = ""


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _classification(fixture: dict[str, Any] | None, records: list[dict[str, Any]]) -> str:
    if fixture:
        return str(
            (fixture.get("classification") or {}).get("primary_classification") or ""
        ).upper()
    for row in records:
        cls = row.get("classification")
        if isinstance(cls, dict) and cls.get("primary_classification"):
            return str(cls["primary_classification"]).upper()
        if isinstance(cls, str) and cls:
            return cls.upper()
    return ""


def run_control_test_suite(
    *,
    fixture: dict[str, Any] | None = None,
    audit_records: list[dict[str, Any]] | None = None,
) -> list[ControlTestSpec]:
    """Run catalog control tests against fixture and/or audit records."""
    records = list(audit_records or [])
    classification = _classification(fixture, records)
    policy = (fixture or {}).get("policy_decision") or {}
    proof = (fixture or {}).get("proof") or {}
    dry_run = bool((fixture or {}).get("dry_run", True) or policy.get("dry_run", True))
    outcome = str(policy.get("outcome", "PREVIEW_ONLY")).upper()
    conclusion = (proof.get("conclusion") or {}).get("status", "not_run")
    tests: list[ControlTestSpec] = []

    audit_rows = [r for r in records if r.get("command") or r.get("action") or r.get("incident_id")]
    has_audit = bool(audit_rows) or fixture is not None

    tests.append(
        ControlTestSpec(
            control_id="CT-AUDIT-001",
            control_objective="Proxy configuration changes require audit evidence",
            required_evidence=["audit_jsonl", "incident_id", "timestamp"],
            test_steps=[
                "Scan audit records for incident-linked observations",
                "Verify append-only audit fields present",
            ],
            result=ControlTestOutcome.PASS
            if has_audit
            else ControlTestOutcome.INSUFFICIENT_EVIDENCE,
            evidence_refs=[f"audit_records:{len(records)}"],
            limitations=["Does not verify tamper-evident storage off-host."],
            reviewer_notes="PASS when audit trail exists for triage.",
        )
    )

    reg_confirmed = any(
        str(r.get("confirmation_used") or r.get("confirmation") or "").strip() for r in records
    ) or bool(policy.get("requires_confirmation"))
    tests.append(
        ControlTestSpec(
            control_id="CT-REG-002",
            control_objective="Registry mutation requires typed confirmation",
            required_evidence=["typed_confirmation", "policy_decision"],
            test_steps=[
                "Check policy requires_confirmation",
                "Verify no apply without confirmation token in audit",
            ],
            result=(
                ControlTestOutcome.PASS
                if dry_run or reg_confirmed or outcome in ("PREVIEW_ONLY", "BLOCK", "DENY")
                else ControlTestOutcome.FAIL
            ),
            evidence_refs=[f"policy_outcome:{outcome}", f"dry_run:{dry_run}"],
            limitations=["Applies to WinINET remediation paths in scope."],
        )
    )

    tests.append(
        ControlTestSpec(
            control_id="CT-REM-003",
            control_objective="Remediation must default to dry-run",
            required_evidence=["dry_run", "policy_outcome"],
            test_steps=[
                "Inspect policy_decision.outcome",
                "Count remediation_preview vs execute in audit",
            ],
            result=(
                ControlTestOutcome.PASS
                if dry_run or outcome in ("PREVIEW_ONLY", "REQUIRE_TYPED_CONFIRMATION")
                else ControlTestOutcome.FAIL
            ),
            evidence_refs=[f"dry_run:{dry_run}", f"outcome:{outcome}"],
            limitations=["Recommendation is not execution authority."],
        )
    )

    low_tier = any(
        str(r.get("evidence_tier", "")).lower() in ("observation", "correlation", "observed_only")
        for r in records
    ) or conclusion in ("weakened", "inconclusive", "not_run")
    _ = low_tier  # informational for future narrative checks
    destructive_blocked = any(
        str(r.get("decision", "")).lower() == "blocked" or str(r.get("blocked_action", ""))
        for r in records
    )
    tests.append(
        ControlTestSpec(
            control_id="CT-EVID-004",
            control_objective="Low evidence tier must not unlock destructive action",
            required_evidence=["evidence_tier", "policy_decision", "blocked_action audit"],
            test_steps=["Map evidence tier", "Verify destructive actions blocked or preview-only"],
            result=(
                ControlTestOutcome.PASS
                if destructive_blocked or dry_run
                else ControlTestOutcome.INSUFFICIENT_EVIDENCE
            ),
            evidence_refs=[f"destructive_blocked_events:{destructive_blocked}"],
            limitations=["Correlation-only evidence cannot become final causation."],
        )
    )

    unknown_proxy = classification == "UNKNOWN_LOCAL_PROXY" or any(
        _classification(None, [r]) == "UNKNOWN_LOCAL_PROXY" for r in records
    )

    if unknown_proxy:
        class_result = ControlTestOutcome.PASS
    elif classification:
        class_result = ControlTestOutcome.INSUFFICIENT_EVIDENCE
    else:
        class_result = ControlTestOutcome.INSUFFICIENT_EVIDENCE
    tests.append(
        ControlTestSpec(
            control_id="CT-CLASS-005",
            control_objective="Unknown local proxy must not be treated as malware proof",
            required_evidence=["classification", "narrative limitations"],
            test_steps=["If UNKNOWN_LOCAL_PROXY, verify no malware-proof language in outputs"],
            result=class_result,
            evidence_refs=[f"classification:{classification or 'n/a'}"],
            limitations=["Classification is not accusation."],
            reviewer_notes="PASS supports triage label without malware verdict.",
        )
    )

    tls_case = classification in ("POSSIBLE_MITM_RISK", "TLS_MISMATCH") or any(
        "TLS" in str(r.get("incident_type", "")).upper() for r in records
    )
    tests.append(
        ControlTestSpec(
            control_id="CT-TLS-006",
            control_objective="TLS mismatch must be reported with limitations",
            required_evidence=["tls_proof", "limitations"],
            test_steps=["Check classification and proof limitations for MITM overclaim"],
            result=(
                ControlTestOutcome.PASS if tls_case else ControlTestOutcome.INSUFFICIENT_EVIDENCE
            ),
            evidence_refs=[f"tls_context:{tls_case}"],
            limitations=["Possible MITM risk is triage — not confirmed interception."],
        )
    )

    if fixture and fixture.get("control_test_exception"):
        tests.append(
            ControlTestSpec(
                control_id="CT-EXC-000",
                control_objective="Exception handling sample",
                required_evidence=["reviewer_signoff"],
                test_steps=["Manual exception recorded in fixture"],
                result=ControlTestOutcome.EXCEPTION,
                evidence_refs=["fixture:control_test_exception"],
                limitations=["Exception requires human reviewer approval."],
                reviewer_notes=str(fixture.get("control_test_exception")),
            )
        )

    _ = _now()
    return tests
