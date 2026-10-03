"""Confidence model for unified evidence reports."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class EvidencePhase(StrEnum):
    """Represent the evidence phase enum.

    Variants:
        OBSERVATION: Structured value carried by this enum.
        HYPOTHESIS: Structured value carried by this enum.
        PROOF: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    OBSERVATION = "Observation"
    HYPOTHESIS = "Hypothesis"
    PROOF = "Proof"


class ConfidenceEntry(BaseModel):
    """Represent the confidence entry type.

    Key fields:
        phase: Structured value carried by this type.
        subject: Structured value carried by this type.
        statement: Structured value carried by this type.
        confidence: Structured value carried by this type.
        limitation: Structured value carried by this type.
        recommended_action: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    phase: EvidencePhase
    subject: str
    statement: str
    confidence: str
    limitation: str = ""
    recommended_action: str = ""

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
        return self.model_dump(mode="json")


def build_confidence_entries(package: dict[str, Any]) -> list[ConfidenceEntry]:
    """Derive confidence-model rows from merged evidence package."""
    entries: list[ConfidenceEntry] = []

    attr = package.get("proxy_writer_attribution") or package.get("attribution") or {}
    if attr:
        entries.append(
            ConfidenceEntry(
                phase=EvidencePhase.OBSERVATION,
                subject="WinINET proxy state",
                statement=str(
                    attr.get("registry_state") or attr.get("snapshot", {}).get("proxy_state", "")
                ),
                confidence=str(attr.get("attribution_confidence") or "medium"),
                limitation="Registry observation is not writer proof unless Sysmon E13 confirms.",
                recommended_action="Review proxy settings; do not modify without typed confirmation.",
            )
        )
        if attr.get("registry_writer_confirmed"):
            entries.append(
                ConfidenceEntry(
                    phase=EvidencePhase.PROOF,
                    subject="Registry writer",
                    statement=str(attr.get("rationale", "")),
                    confidence="high",
                    limitation="Writer proof depends on telemetry quality and time window.",
                    recommended_action="Correlate writer process with change management records.",
                )
            )
        else:
            entries.append(
                ConfidenceEntry(
                    phase=EvidencePhase.HYPOTHESIS,
                    subject="Proxy attribution",
                    statement=str(attr.get("classification", "")),
                    confidence=str(attr.get("attribution_confidence") or "low"),
                    limitation="; ".join(attr.get("limitations", [])[:2]),
                    recommended_action="Enable Sysmon Event ID 13 for stronger attribution.",
                )
            )

    tls = package.get("tls_proof") or {}
    if tls:
        entries.append(
            ConfidenceEntry(
                phase=EvidencePhase.PROOF
                if tls.get("certificate_mismatch")
                else EvidencePhase.OBSERVATION,
                subject="TLS path contrast",
                statement=f"MITM risk: {tls.get('mitm_risk_level')}; mismatch={tls.get('certificate_mismatch')}",
                confidence="medium" if tls.get("certificate_mismatch") else "high",
                limitation="; ".join(tls.get("limitations", [])[:1]),
                recommended_action="Compare with expected corporate TLS inspection policy.",
            )
        )

    web = package.get("website_risk") or {}
    if web:
        entries.append(
            ConfidenceEntry(
                phase=EvidencePhase.HYPOTHESIS,
                subject="Website risk",
                statement=f"Risk {web.get('risk_level')} score={web.get('score')}",
                confidence="low" if web.get("risk_level") == "UNKNOWN" else "medium",
                limitation="; ".join(web.get("limitations", [])[:2]),
                recommended_action="Do not treat as antivirus verdict — verify with security team.",
            )
        )

    proof = package.get("proof_results") or {}
    if proof:
        entries.append(
            ConfidenceEntry(
                phase=EvidencePhase.PROOF,
                subject="Network path proof",
                statement=str(proof.get("outcome", "")),
                confidence=str(proof.get("confidence_level", "medium")),
                limitation="Path contrast does not prove registry authorship.",
                recommended_action="Use proxy-disable preview only after explicit confirmation.",
            )
        )

    return entries
