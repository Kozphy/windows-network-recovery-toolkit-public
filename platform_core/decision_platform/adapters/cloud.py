"""Cloud domain adapter — service health and failover preview (fixture-driven).

Operational signals: service health, error budget remaining, regional failover readiness.
Does not trigger cloud API failover — preview decisions only.
"""

from __future__ import annotations

from typing import Any

from ..adapter import AdapterContext, DomainAdapter
from ..models import Evidence, Observation, PlatformDomain


class CloudAdapter(DomainAdapter):
    """Adapter for cloud operational health and failover preview decisions."""

    @property
    def domain(self) -> PlatformDomain:
        """Provide domain behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return PlatformDomain.CLOUD

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
                signal="service_health",
                value=payload.get("service_health", "degraded"),
                confidence=0.75,
                source_ref="fixture:cloud_monitor",
            ),
            Observation(
                domain=self.domain.value,
                signal="error_budget_remaining",
                value=float(payload.get("error_budget_pct", 12.0)),
                confidence=0.8,
            ),
            Observation(
                domain=self.domain.value,
                signal="regional_failover_available",
                value=bool(payload.get("failover_ready", True)),
                confidence=0.7,
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
        return [
            Evidence(
                evidence_id=f"cloud_{obs.signal}",
                domain=self.domain.value,
                label=f"{obs.signal}={obs.value}",
                kind="observation",
                weight=0.6,
                supports_decision=obs.signal != "service_health" or obs.value != "healthy",
                observation_ids=[obs.observation_id],
            )
            for obs in observations
        ]

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
                "decision_id": "cloud_failover_preview",
                "label": "Preview regional failover",
                "base_benefit": 60.0,
                "base_risk": 30.0,
                "risk_factors": {"data_replication_lag": 15.0},
            },
            {
                "decision_id": "cloud_scale_out",
                "label": "Scale out replicas",
                "base_benefit": 48.0,
                "base_risk": 18.0,
            },
        ]
