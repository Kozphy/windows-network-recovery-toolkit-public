"""Mature control test records for technology risk governance reporting."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MatureTestResult(StrEnum):
    """Represent the mature test result enum.

    Variants:
        PASS: Structured value carried by this enum.
        FAIL: Structured value carried by this enum.
        PARTIAL: Structured value carried by this enum.
        NOT_TESTED: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_TESTED = "NOT_TESTED"


class ControlTestMatureRecord(BaseModel):
    """Represent the control test mature record type.

    Key fields:
        control_id: Structured value carried by this type.
        control_name: Structured value carried by this type.
        control_objective: Structured value carried by this type.
        test_procedure: Structured value carried by this type.
        evidence_required: Structured value carried by this type.
        test_result: Structured value carried by this type.
        residual_risk: Structured value carried by this type.
        limitation: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    control_id: str
    control_name: str
    control_objective: str
    test_procedure: str
    evidence_required: list[str] = Field(default_factory=list)
    test_result: MatureTestResult
    residual_risk: str = ""
    limitation: str = ""
    remediation_owner: str = "IT Operations"
    review_frequency: str = "Per incident / quarterly control review"


_CATALOG: dict[str, dict[str, str]] = {
    "DEAD_PROXY_CONFIG": {
        "control_id": "CTRL-EPR-001",
        "control_name": "Dead WinINET proxy detection",
        "control_objective": "Detect WinINET proxy pointing to localhost without active listener before remediation",
        "test_procedure": "Compare WinINET ProxyServer to localhost listener state; require proof tier T1+",
        "evidence_required": "wininet_proxy_server,listener_found,proof.conclusion",
        "remediation_owner": "IT Support",
    },
    "WININET_WINHTTP_MISMATCH": {
        "control_id": "CTRL-EPR-002",
        "control_name": "WinINET / WinHTTP stack alignment",
        "control_objective": "Identify inconsistent proxy configuration across WinINET and WinHTTP",
        "test_procedure": "Contrast WinINET proxy settings with WinHTTP direct-access flags",
        "evidence_required": "wininet_proxy_enabled,winhttp_direct_access,classification.secondary_signals",
        "remediation_owner": "Endpoint reliability team",
    },
    "LOCAL_PROXY_ACTIVE": {
        "control_id": "CTRL-EPR-003",
        "control_name": "Local proxy listener governance",
        "control_objective": "Validate localhost proxy has attributed listener when enabled",
        "test_procedure": "Confirm listener_found and optional writer attribution tier",
        "evidence_required": "listener_info,proxy_owner.process",
        "remediation_owner": "Platform engineering",
    },
    "PAC_CONFIGURED": {
        "control_id": "CTRL-EPR-004",
        "control_name": "PAC configuration review",
        "control_objective": "Ensure PAC URL changes are observable and change-managed",
        "test_procedure": "Inspect wininet_auto_config_url / PAC fetch evidence when present",
        "evidence_required": "wininet_auto_config_url,pac_url",
        "remediation_owner": "IT Governance",
    },
    "UNKNOWN_LOCAL_PROXY": {
        "control_id": "CTRL-EPR-005",
        "control_name": "Unknown local proxy triage",
        "control_objective": "Prevent malware verdict without writer attribution proof",
        "test_procedure": "Require human review when listener exists without proven registry writer",
        "evidence_required": "classification,writer_attribution,limitations",
        "remediation_owner": "Cyber risk triage",
    },
    "REVERTER_SUSPECTED": {
        "control_id": "CTRL-EPR-006",
        "control_name": "Proxy reverter monitoring",
        "control_objective": "Detect proxy settings returning after remediation preview",
        "test_procedure": "Review proxy-watch timeline and repeated enable events",
        "evidence_required": "proxy_watch,audit_log_entries,reverter_signals",
        "remediation_owner": "Security operations / Endpoint reliability",
    },
}


def _classification(fixture: dict[str, Any]) -> str:
    return str((fixture.get("classification") or {}).get("primary_classification") or "").upper()


def _secondary(fixture: dict[str, Any]) -> list[str]:
    return list((fixture.get("classification") or {}).get("secondary_signals") or [])


def _listener(fixture: dict[str, Any]) -> bool | None:
    owner = fixture.get("proxy_owner") or fixture.get("listener_info") or {}
    if "listener_found" in owner:
        return bool(owner.get("listener_found"))
    return None


def _pac_configured(fixture: dict[str, Any]) -> bool:
    proxy = fixture.get("proxy_state") or fixture.get("proxy_status") or {}
    pac = str(proxy.get("wininet_auto_config_url") or proxy.get("pac_url") or "").strip()
    return bool(pac)


def _evaluate_scenario(key: str, fixture: dict[str, Any]) -> MatureTestResult:
    primary = _classification(fixture)
    secondary = _secondary(fixture)
    listener = _listener(fixture)
    proof = (fixture.get("proof") or {}).get("conclusion") or {}
    proof_status = proof.get("status", "not_run")

    if key == "DEAD_PROXY_CONFIG":
        if primary != "DEAD_PROXY_CONFIG" and "DEAD_LOCALHOST_PORT" not in secondary:
            return MatureTestResult.NOT_TESTED
        if listener is False and primary == "DEAD_PROXY_CONFIG":
            return (
                MatureTestResult.PASS
                if proof_status in ("supported", "failed")
                else MatureTestResult.PARTIAL
            )
        return MatureTestResult.PARTIAL

    if key == "WININET_WINHTTP_MISMATCH":
        if primary == "WININET_WINHTTP_MISMATCH" or "WININET_WINHTTP_MISMATCH" in secondary:
            return MatureTestResult.PASS
        return MatureTestResult.NOT_TESTED

    if key == "LOCAL_PROXY_ACTIVE":
        if primary in ("LOCAL_PROXY_ACTIVE", "LOCAL_PROXY_ENABLED") or (
            listener is True and primary not in ("UNKNOWN_LOCAL_PROXY",)
        ):
            return MatureTestResult.PASS if listener else MatureTestResult.FAIL
        return MatureTestResult.NOT_TESTED

    if key == "PAC_CONFIGURED":
        if _pac_configured(fixture) or primary == "PAC_CONFIGURED":
            return MatureTestResult.PASS if _pac_configured(fixture) else MatureTestResult.PARTIAL
        return MatureTestResult.NOT_TESTED

    if key == "UNKNOWN_LOCAL_PROXY":
        if primary == "UNKNOWN_LOCAL_PROXY":
            writer = fixture.get("writer_attribution") or {}
            if writer.get("attribution_tier") == "PROVEN_REGISTRY_WRITER":
                return MatureTestResult.PARTIAL
            return MatureTestResult.PASS
        return MatureTestResult.NOT_TESTED

    if key == "REVERTER_SUSPECTED":
        if primary == "REVERTER_SUSPECTED" or fixture.get("reverter_signals"):
            return MatureTestResult.PASS if fixture.get("proxy_watch") else MatureTestResult.PARTIAL
        return MatureTestResult.NOT_TESTED

    return MatureTestResult.NOT_TESTED


def _residual_risk(key: str, result: MatureTestResult) -> str:
    if result == MatureTestResult.PASS:
        return "Low residual for scoped control objective — monitor for recurrence"
    if result == MatureTestResult.PARTIAL:
        return "Medium — additional evidence or human review recommended"
    if result == MatureTestResult.FAIL:
        return "High — control objective not met for incident class"
    return "Not assessed — scenario out of scope for fixture"


def run_mature_control_tests(fixture: dict[str, Any]) -> list[ControlTestMatureRecord]:
    """Run classification-scoped mature control tests for governance reporting."""
    records: list[ControlTestMatureRecord] = []
    for key, meta in _CATALOG.items():
        result = _evaluate_scenario(key, fixture)
        records.append(
            ControlTestMatureRecord(
                control_id=meta["control_id"],
                control_name=meta["control_name"],
                control_objective=meta["control_objective"],
                test_procedure=meta["test_procedure"],
                evidence_required=[
                    e.strip() for e in meta["evidence_required"].split(",") if e.strip()
                ],
                test_result=result,
                residual_risk=_residual_risk(key, result),
                limitation="Control test evaluates design effectiveness for fixture scope — not regulatory attestation.",
                remediation_owner=meta["remediation_owner"],
            )
        )
    return records
