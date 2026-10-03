"""Typed evidence record — ordinal confidence, chain of custody, deterministic serialization."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from src.platform_core import SCHEMA_VERSION
from src.platform_core.contracts import EvidenceItem, EvidenceTierName
from src.platform_core.serialization import canonical_json, content_hash

ConfidenceOrdinal = Literal["very_low", "low", "medium", "high", "very_high"]


class ChainOfCustody(BaseModel):
    """Metadata for audit defensibility — who collected what, when, how."""

    collector_id: str
    collector_version: str = "1.0"
    host_id: str = "local"
    session_id: str = ""
    collected_at_utc: str
    integrity_hash: str = ""
    parent_evidence_id: str = ""


class TypedEvidenceRecord(BaseModel):
    """Canonical evidence atom for ERP diagnostics."""

    evidence_id: str
    schema_version: str = SCHEMA_VERSION
    source: str
    timestamp: str
    collector: str
    evidence_type: str
    observed_value: str = ""
    confidence_level: ConfidenceOrdinal = "medium"
    evidence_tier: EvidenceTierName = "OBSERVED_ONLY"
    limitations: list[str] = Field(default_factory=list)
    raw_reference: str = ""
    chain_of_custody: ChainOfCustody
    event_id: str = ""
    signal: str = ""

    @field_validator("confidence_level", mode="before")
    @classmethod
    def _reject_probability(cls, v: Any) -> Any:
        if isinstance(v, float):
            raise ValueError(
                "confidence_level must be ordinal (very_low..very_high), not a probability float"
            )
        return v

    def integrity_hash(self) -> str:
        """Return integrity hash.

        Returns:
            The computed `str` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        payload = self.model_dump(mode="json")
        payload.pop("chain_of_custody", None)
        coc = self.chain_of_custody.model_dump(mode="json")
        coc.pop("integrity_hash", None)
        payload["chain_of_custody"] = coc
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def with_integrity(self) -> TypedEvidenceRecord:
        """Return with integrity.

        Returns:
            The computed `TypedEvidenceRecord` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        coc = self.chain_of_custody.model_copy(update={"integrity_hash": self.integrity_hash()})
        return self.model_copy(update={"chain_of_custody": coc})

    def to_evidence_item(self) -> EvidenceItem:
        """Return to evidence item.

        Returns:
            The computed `EvidenceItem` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ordinal_map = {
            "very_low": 0.2,
            "low": 0.35,
            "medium": 0.5,
            "high": 0.7,
            "very_high": 0.85,
        }
        return EvidenceItem(
            evidence_id=self.evidence_id,
            event_id=self.event_id or self.evidence_id,
            timestamp_utc=self.timestamp,
            source=self.source,
            signal=self.signal or self.evidence_type,
            observed_value=self.observed_value,
            tier=self.evidence_tier,
            confidence=ordinal_map.get(self.confidence_level, 0.5),
            raw_data={
                "collector": self.collector,
                "evidence_type": self.evidence_type,
                "confidence_level": self.confidence_level,
                "limitations": self.limitations,
                "raw_reference": self.raw_reference,
                "chain_of_custody": self.chain_of_custody.model_dump(mode="json"),
            },
        )

    @classmethod
    def from_observation(
        cls,
        *,
        source: str,
        collector: str,
        evidence_type: str,
        observed_value: str,
        confidence_level: ConfidenceOrdinal = "medium",
        evidence_tier: EvidenceTierName = "OBSERVED_ONLY",
        limitations: list[str] | None = None,
        raw_reference: str = "",
        event_id: str = "",
        signal: str = "",
        host_id: str = "local",
    ) -> TypedEvidenceRecord:
        """Return from observation.

        Args:
            source: source supplied by the caller.
            collector: collector supplied by the caller.
            evidence_type: evidence type supplied by the caller.
            observed_value: observed value supplied by the caller.
            confidence_level: confidence level supplied by the caller.
            evidence_tier: evidence tier supplied by the caller.
            limitations: limitations supplied by the caller.
            raw_reference: raw reference supplied by the caller.
            event_id: event id supplied by the caller.
            signal: signal supplied by the caller.
            host_id: host id supplied by the caller.

        Returns:
            The computed `TypedEvidenceRecord` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        eid = f"ev-{uuid.uuid4().hex[:12]}"
        rec = cls(
            evidence_id=eid,
            source=source,
            timestamp=ts,
            collector=collector,
            evidence_type=evidence_type,
            observed_value=observed_value,
            confidence_level=confidence_level,
            evidence_tier=evidence_tier,
            limitations=limitations or [],
            raw_reference=raw_reference,
            event_id=event_id,
            signal=signal or evidence_type,
            chain_of_custody=ChainOfCustody(
                collector_id=collector,
                host_id=host_id,
                collected_at_utc=ts,
            ),
        )
        return rec.with_integrity()


def records_to_bundle(
    records: list[TypedEvidenceRecord],
    *,
    incident_id: str,
    tier: EvidenceTierName = "OBSERVED_ONLY",
    summary: str = "",
) -> dict[str, Any]:
    """Serialize records for deterministic replay fixtures."""
    return {
        "incident_id": incident_id,
        "schema_version": SCHEMA_VERSION,
        "tier": tier,
        "summary": summary,
        "records": [r.model_dump(mode="json") for r in records],
        "bundle_hash": content_hash([r.model_dump(mode="json") for r in records]),
    }


def records_from_fixture(data: dict[str, Any]) -> list[TypedEvidenceRecord]:
    """Return records from fixture.

    Args:
        data: data supplied by the caller.

    Returns:
        The computed `list[TypedEvidenceRecord]` value.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return [TypedEvidenceRecord.model_validate(r) for r in data.get("records", [])]
