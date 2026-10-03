"""Incident timeline builder — normalizes proxy, probe, remediation, audit events."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from src.platform_core.attribution.models import AttributionSnapshot
from src.platform_core.evidence.record import TypedEvidenceRecord
from src.platform_core.proof.models import ProofResult

from .models import TimelineEntry


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class IncidentTimelineBuilder:
    """Build chronological, audit-ready incident timeline."""

    def __init__(self, *, incident_id: str | None = None) -> None:
        """Initialize the incident timeline builder instance.

        Args:
            incident_id: incident id supplied by the caller.

        Returns:
            None.

        Side effects:
            None.
        """
        self.incident_id = incident_id or f"incident-{uuid.uuid4().hex[:12]}"
        self._entries: list[TimelineEntry] = []

    def add_entry(self, entry: TimelineEntry) -> None:
        """Return add entry.

        Args:
            entry: entry supplied by the caller.

        Returns:
            None.

        Side effects:
            None.
        """
        self._entries.append(entry)

    def add_proxy_state(self, snapshot: AttributionSnapshot) -> None:
        """Return add proxy state.

        Args:
            snapshot: snapshot supplied by the caller.

        Returns:
            None.

        Side effects:
            None.
        """
        ps = snapshot.proxy_state
        self._entries.append(
            TimelineEntry(
                timestamp=snapshot.timestamp_utc,
                event_type="proxy_state_observed",
                actor="collector:proxy_attribution",
                object="WinINET/WinHTTP",
                after_state=(
                    f"ProxyEnable={ps.wininet_proxy_enable}; "
                    f"ProxyServer={ps.wininet_proxy_server or 'none'}"
                ),
                evidence_refs=[snapshot.snapshot_id],
                confidence_level="high",
                limitations=["Registry observation is not writer proof."],
            )
        )
        if snapshot.listener.pid:
            self._entries.append(
                TimelineEntry(
                    timestamp=snapshot.timestamp_utc,
                    event_type="listener_owner_correlated",
                    actor="collector:netstat",
                    object=f"127.0.0.1:{ps.localhost_port}",
                    after_state=f"{snapshot.listener.process_name} pid={snapshot.listener.pid}",
                    evidence_refs=[snapshot.snapshot_id],
                    confidence_level="medium",
                    limitations=snapshot.limitations,
                )
            )
        self._entries.append(
            TimelineEntry(
                timestamp=snapshot.timestamp_utc,
                event_type="listener_classified",
                actor="classifier:proxy_attribution",
                object=snapshot.classification.value,
                after_state=snapshot.classification_rationale,
                evidence_refs=[snapshot.snapshot_id],
                confidence_level="medium",
                limitations=snapshot.limitations,
            )
        )

    def add_proof_result(self, proof: ProofResult) -> None:
        """Return add proof result.

        Args:
            proof: proof supplied by the caller.

        Returns:
            None.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        for obs in proof.observations:
            self._entries.append(
                TimelineEntry(
                    timestamp=proof.timestamp_utc,
                    event_type=f"probe_{obs.probe_type}",
                    actor="collector:proof_engine",
                    object=proof.target_url,
                    after_state=obs.observed_value,
                    evidence_refs=[proof.proof_id, obs.probe_id],
                    confidence_level="high" if obs.success else "medium",
                    limitations=obs.limitations,
                )
            )
        self._entries.append(
            TimelineEntry(
                timestamp=proof.timestamp_utc,
                event_type="proof_classified",
                actor="engine:proof",
                object=proof.outcome.value,
                after_state=proof.outcome_rationale,
                evidence_refs=[proof.proof_id],
                confidence_level=proof.confidence_level,  # type: ignore[arg-type]
                limitations=proof.limitations
                + ["Proof classification is path contrast, not attribution verdict."],
            )
        )

    def add_evidence_records(self, records: list[TypedEvidenceRecord]) -> None:
        """Return add evidence records.

        Args:
            records: records supplied by the caller.

        Returns:
            None.

        Side effects:
            Records data in the configured store or telemetry sink.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        for rec in records:
            self._entries.append(
                TimelineEntry(
                    timestamp=rec.timestamp,
                    event_type=f"evidence_{rec.evidence_type}",
                    actor=f"collector:{rec.collector}",
                    object=rec.signal or rec.evidence_type,
                    after_state=rec.observed_value,
                    evidence_refs=[rec.evidence_id],
                    confidence_level=rec.confidence_level,
                    limitations=rec.limitations,
                )
            )

    def add_remediation_preview(
        self, preview: dict[str, Any], *, timestamp: str | None = None
    ) -> None:
        """Return add remediation preview.

        Args:
            preview: preview supplied by the caller.
            timestamp: timestamp supplied by the caller.

        Returns:
            None.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ts = timestamp or _now()
        for item in preview.get("previews", []):
            self._entries.append(
                TimelineEntry(
                    timestamp=ts,
                    event_type="remediation_preview",
                    actor="planner:remediation",
                    object=str(item.get("action_id", "unknown")),
                    after_state=str(item.get("mutations", []))[:500],
                    confidence_level="high",
                    limitations=["Preview only — no mutation performed."],
                )
            )

    def add_audit_record(self, audit: dict[str, Any]) -> None:
        """Return add audit record.

        Args:
            audit: audit supplied by the caller.

        Returns:
            None.

        Side effects:
            Records data in the configured store or telemetry sink.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        self._entries.append(
            TimelineEntry(
                timestamp=str(audit.get("timestamp_utc") or audit.get("timestamp") or _now()),
                event_type=f"audit_{audit.get('action_type', 'record')}",
                actor=str(audit.get("actor", "platform")),
                object=str(audit.get("decision_id") or audit.get("audit_id", "")),
                after_state=str(audit.get("payload", audit))[:400],
                evidence_refs=[str(audit.get("audit_id", ""))],
                confidence_level="very_high",
                limitations=[],
            )
        )

    def build(self) -> list[dict[str, Any]]:
        """Build the requested value.

        Returns:
            The computed `list[dict[str, Any]]` value.

        Side effects:
            None.
        """
        ordered = sorted(self._entries, key=lambda e: e.timestamp)
        return [e.to_dict() for e in ordered]
