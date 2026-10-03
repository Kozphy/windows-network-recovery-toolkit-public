"""Multievidence hypothesis engine — detection-oriented models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.platform_core import SCHEMA_VERSION

EvidenceTierName = Literal[
    "OBSERVED_ONLY",
    "CORRELATED",
    "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION",
]

ConfidenceRank = Literal["low", "medium", "high"]


class EvidenceKind(StrEnum):
    """Represent the evidence kind enum.

    Variants:
        REGISTRY: Structured value carried by this enum.
        PROCESS: Structured value carried by this enum.
        TIMELINE: Structured value carried by this enum.
        NETWORK: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    REGISTRY = "registry"
    PROCESS = "process"
    TIMELINE = "timeline"
    NETWORK = "network"


class EvidenceRef(BaseModel):
    """Single cited evidence item with tier — observation vs proof explicit."""

    evidence_id: str
    kind: EvidenceKind
    signal: str
    tier: EvidenceTierName = "OBSERVED_ONLY"
    observed_value: str = ""
    summary: str = ""
    is_proof: bool = False


class RegistryEvidence(BaseModel):
    """Represent the registry evidence type.

    Key fields:
        evidence_id: Structured value carried by this type.
        tier: Structured value carried by this type.
        proxy_enable: Structured value carried by this type.
        proxy_server: Structured value carried by this type.
        winhttp_direct: Structured value carried by this type.
        auto_config_url: Structured value carried by this type.
        writer_confirmed: Structured value carried by this type.
        writer_process: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    evidence_id: str = "reg-001"
    tier: EvidenceTierName = "OBSERVED_ONLY"
    proxy_enable: int | None = None
    proxy_server: str | None = None
    winhttp_direct: bool | None = None
    auto_config_url: str | None = None
    writer_confirmed: bool = False
    writer_process: str | None = None
    writer_telemetry: list[str] = Field(default_factory=list)


class ProcessEvidence(BaseModel):
    """Represent the process evidence type.

    Key fields:
        evidence_id: Structured value carried by this type.
        tier: Structured value carried by this type.
        listener_found: Structured value carried by this type.
        localhost_port: Structured value carried by this type.
        pid: Structured value carried by this type.
        process_name: Structured value carried by this type.
        signed_status: Structured value carried by this type.
        known_dev_tool: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    evidence_id: str = "proc-001"
    tier: EvidenceTierName = "CORRELATED"
    listener_found: bool = False
    localhost_port: int | None = None
    pid: int | None = None
    process_name: str | None = None
    signed_status: str | None = None
    known_dev_tool: bool = False
    known_security_tool: bool = False


class TimelineEvent(BaseModel):
    """Represent the timeline event type.

    Key fields:
        timestamp_utc: Structured value carried by this type.
        signal: Structured value carried by this type.
        observed_value: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    timestamp_utc: str
    signal: str
    observed_value: str = ""


class TimelineEvidence(BaseModel):
    """Represent the timeline evidence type.

    Key fields:
        evidence_id: Structured value carried by this type.
        events: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    evidence_id: str = "tl-001"
    events: list[TimelineEvent] = Field(default_factory=list)


class NetworkEvidence(BaseModel):
    """Represent the network evidence type.

    Key fields:
        evidence_id: Structured value carried by this type.
        tier: Structured value carried by this type.
        dns_ok: Structured value carried by this type.
        ping_ok: Structured value carried by this type.
        browser_https_ok: Structured value carried by this type.
        direct_path_ok: Structured value carried by this type.
        proxied_path_ok: Structured value carried by this type.
        tls_cert_mismatch: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    evidence_id: str = "net-001"
    tier: EvidenceTierName = "OBSERVED_ONLY"
    dns_ok: bool | None = None
    ping_ok: bool | None = None
    browser_https_ok: bool | None = None
    direct_path_ok: bool | None = None
    proxied_path_ok: bool | None = None
    tls_cert_mismatch: bool | None = None
    vpn_active: bool | None = None
    vpn_split_tunnel: bool | None = None


class MultievidenceInput(BaseModel):
    """Four-domain evidence bundle for hypothesis evaluation."""

    incident_id: str
    schema_version: str = SCHEMA_VERSION
    registry: RegistryEvidence | None = None
    process: ProcessEvidence | None = None
    timeline: TimelineEvidence | None = None
    network: NetworkEvidence | None = None


class HypothesisEvaluation(BaseModel):
    """Single hypothesis with required detection-engine output fields."""

    hypothesis_id: str
    title: str
    hypothesis: str
    confidence: float = Field(ge=0.0, le=0.98)
    confidence_rank: ConfidenceRank
    confidence_display: str
    confidence_explanation: str
    supporting_evidence: list[EvidenceRef]
    missing_evidence: list[str]
    alternative_explanations: list[str] = Field(default_factory=list)
    recommended_actions: list[str]
    limitations: list[str] = Field(default_factory=list)
    incident_type: str = ""


class HypothesisEngineResult(BaseModel):
    """Ranked hypothesis set — primary + mandatory alternatives."""

    incident_id: str
    schema_version: str = SCHEMA_VERSION
    primary: HypothesisEvaluation
    alternatives: list[HypothesisEvaluation]
    epistemic_notice: str = (
        "Hypotheses are competing explanations, not confirmed root causes. "
        "Confidence is ordinal — not probability or certainty."
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

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
