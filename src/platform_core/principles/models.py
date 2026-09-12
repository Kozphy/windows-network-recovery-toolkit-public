"""Pydantic models for epistemic principle validation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class Observation(BaseModel):
    """Tier-1 fact — registry, netstat, or path read without proof upgrade."""

    signal: str
    value: str | bool | int | float | None = None
    source: str = "unknown"
    tier: Literal["OBSERVED_ONLY"] = "OBSERVED_ONLY"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProofEnvelope(BaseModel):
    """Structured proof attempt bundle — observation upgraded only when checks pass."""

    hypothesis: str = ""
    proof_attempts: list[dict[str, Any]] = Field(default_factory=list)
    conclusion_status: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)
    proof_tier: Literal["OBSERVED_ONLY", "CORRELATED", "PROVEN"] = "OBSERVED_ONLY"

    @property
    def has_structured_proof(self) -> bool:
        """Return has structured proof.

        Returns:
            The computed `bool` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        if self.conclusion_status.lower() in {"supported", "confirmed", "proven"}:
            return True
        return any(
            str(a.get("status", "")).lower() in {"passed", "supported", "confirmed"}
            for a in self.proof_attempts
        )


class Attribution(BaseModel):
    """Listener or registry-writer attribution — correlation unless writer proof exists."""

    listener_found: bool = False
    process_name: str | None = None
    pid: int | None = None
    registry_writer_confirmed: bool = False
    telemetry_sources: list[str] = Field(default_factory=list)
    classification: str = ""
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @property
    def has_writer_telemetry(self) -> bool:
        """Return has writer telemetry.

        Returns:
            The computed `bool` value.

        Side effects:
            Writes output to the requested destination.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        writer_sources = {"sysmon_e13", "procmon", "etw_registry", "sysmon", "event_id_13"}
        return self.registry_writer_confirmed or bool(
            writer_sources.intersection({s.lower() for s in self.telemetry_sources})
        )


class RiskDecision(BaseModel):
    """Classification output with explicit limitations."""

    primary_classification: str = ""
    secondary_signals: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: str = "medium"
    limitations: list[str] = Field(default_factory=list)
    narrative: str = ""


class PolicyDecision(BaseModel):
    """Policy gate outcome with required safety controls."""

    action: str = ""
    outcome: str = "PREVIEW_ONLY"
    allowed: bool = False
    requires_confirmation: bool = True
    confirmation_token: str = ""
    dry_run: bool = True
    rollback_plan_present: bool = False
    monitoring_recommended: bool = True
    audit_logging: bool = True
    safety_checks: list[str] = Field(default_factory=list)


class PrincipleCheck(BaseModel):
    """Represent the principle check type.

    Key fields:
        principle_id: Structured value carried by this type.
        title: Structured value carried by this type.
        passed: Structured value carried by this type.
        violations: Structured value carried by this type.
        guidance: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    principle_id: str
    title: str
    passed: bool
    violations: list[str] = Field(default_factory=list)
    guidance: list[str] = Field(default_factory=list)


class PrincipleComplianceResult(BaseModel):
    """Represent the principle compliance result type.

    Key fields:
        compliant: Structured value carried by this type.
        checks: Structured value carried by this type.
        blocked_overclaims: Structured value carried by this type.
        confidence_display: Structured value carried by this type.
        summary: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    compliant: bool
    checks: list[PrincipleCheck] = Field(default_factory=list)
    blocked_overclaims: list[str] = Field(default_factory=list)
    confidence_display: str = ""
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return self.model_dump()
