"""TLS / MITM evidence models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MitmRiskLevel(StrEnum):
    """Represent the mitm risk level enum.

    Variants:
        LOW: Structured value carried by this enum.
        MEDIUM: Structured value carried by this enum.
        HIGH: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TlsCertificateSnapshot(BaseModel):
    """Represent the tls certificate snapshot type.

    Key fields:
        path: Structured value carried by this type.
        subject: Structured value carried by this type.
        issuer: Structured value carried by this type.
        san: Structured value carried by this type.
        not_before: Structured value carried by this type.
        not_after: Structured value carried by this type.
        serial_number: Structured value carried by this type.
        fingerprint_sha256: Structured value carried by this type.

    Side effects:
        None.
    """

    path: str  # direct | proxied
    subject: str = ""
    issuer: str = ""
    san: list[str] = Field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""
    chain: list[str] = Field(default_factory=list)
    raw_error: str = ""


class RootCaObservation(BaseModel):
    """Represent the root ca observation type.

    Key fields:
        subject: Structured value carried by this type.
        issuer: Structured value carried by this type.
        thumbprint: Structured value carried by this type.
        not_before: Structured value carried by this type.
        not_after: Structured value carried by this type.
        store: Structured value carried by this type.
        suspicious: Structured value carried by this type.
        suspicion_reason: Structured value carried by this type.

    Side effects:
        None.
    """

    subject: str = ""
    issuer: str = ""
    thumbprint: str = ""
    not_before: str = ""
    not_after: str = ""
    store: str = ""
    suspicious: bool = False
    suspicion_reason: str = ""


class TlsProofResult(BaseModel):
    """Represent the tls proof result type.

    Key fields:
        proof_id: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        target_url: Structured value carried by this type.
        direct_cert: Structured value carried by this type.
        proxied_cert: Structured value carried by this type.
        certificate_mismatch: Structured value carried by this type.
        mismatch_fields: Structured value carried by this type.
        mitm_risk_level: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    proof_id: str
    timestamp_utc: str
    target_url: str
    direct_cert: TlsCertificateSnapshot
    proxied_cert: TlsCertificateSnapshot | None = None
    certificate_mismatch: bool = False
    mismatch_fields: list[str] = Field(default_factory=list)
    mitm_risk_level: MitmRiskLevel = MitmRiskLevel.LOW
    root_ca_observations: list[RootCaObservation] = Field(default_factory=list)
    suspicious_roots: list[RootCaObservation] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.
        """
        return self.model_dump(mode="json")
