"""Security domain adapter — incidents, IOC verification, containment previews.

Fixture-driven SIEM-style inputs (severity, verified IOC, affected asset count).
Does not isolate hosts or mutate firewall rules — outputs ranked preview decisions only.
"""

from __future__ import annotations

from typing import Any

from ..adapter import AdapterContext, DomainAdapter
from ..models import Evidence, Observation, PlatformDomain


class SecurityAdapter(DomainAdapter):
    """Adapter for security incident triage and containment preview decisions."""

    @property
    def domain(self) -> PlatformDomain:
        """Provide domain behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return PlatformDomain.SECURITY

    def collect_observations(self, context: AdapterContext) -> list[Observation]:
        """Collect observations for toolkit workflows.

        Args:
            context: Value supplied by the caller for context.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May read local system, file, or network state through configured providers.
        """
        payload = context.payload
        return [
            Observation(
                domain=self.domain.value,
                signal="alert_severity",
                value=payload.get("severity", "high"),
                confidence=0.7,
                source_ref=payload.get("source_ref", "fixture:siem"),
            ),
            Observation(
                domain=self.domain.value,
                signal="verified_ioc",
                value=payload.get("verified_ioc", False),
                confidence=0.9 if payload.get("verified_ioc") else 0.4,
                source_ref="fixture:threat_intel",
            ),
            Observation(
                domain=self.domain.value,
                signal="affected_asset_count",
                value=int(payload.get("affected_assets", 1)),
                confidence=0.8,
            ),
        ]

    def derive_evidence(self, observations: list[Observation]) -> list[Evidence]:
        """Derive evidence for toolkit workflows.

        Args:
            observations: Value supplied by the caller for observations.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        evidence: list[Evidence] = []
        for obs in observations:
            if obs.signal == "alert_severity":
                evidence.append(
                    Evidence(
                        evidence_id="alert_severity",
                        domain=self.domain.value,
                        label=f"Security alert severity={obs.value}",
                        kind="observation",
                        weight=0.75,
                        supports_decision=True,
                        observation_ids=[obs.observation_id],
                    )
                )
            if obs.signal == "verified_ioc":
                evidence.append(
                    Evidence(
                        evidence_id="verified_ioc",
                        domain=self.domain.value,
                        label="IOC verification status",
                        kind="proof" if obs.value else "counter_evidence",
                        weight=0.85,
                        supports_decision=bool(obs.value),
                        detail="Unverified IOC limits containment confidence",
                        observation_ids=[obs.observation_id],
                    )
                )
        return evidence

    def build_candidate_specs(self, context: AdapterContext) -> list[dict[str, Any]]:
        """Build candidate specs for toolkit workflows.

        Args:
            context: Value supplied by the caller for context.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return [
            {
                "decision_id": "sec_isolate_preview",
                "label": "Preview isolation playbook",
                "base_benefit": 50.0,
                "base_risk": 35.0,
                "risk_factors": {"service_disruption": 20.0},
            },
            {
                "decision_id": "sec_monitor_triage",
                "label": "Monitor and triage",
                "base_benefit": 40.0,
                "base_risk": 18.0,
            },
        ]
