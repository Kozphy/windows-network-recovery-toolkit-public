"""Market events domain adapter — catalyst calendar research (no trade execution).

Loads calendar rows via :mod:`src.market_events.calendar`. Research signals only —
does not place orders or move capital.

Input assumptions:
    ``payload["event_id"]`` defaults to ``CPI_2026_06``.
    ``fixture_path`` overrides default calendar location when set on context.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.market_events.calendar import get_event

from ..adapter import AdapterContext, DomainAdapter
from ..models import Evidence, Observation, PlatformDomain


class MarketAdapter(DomainAdapter):
    """Adapter for macro/crypto calendar catalyst research decisions."""

    @property
    def domain(self) -> PlatformDomain:
        """Provide domain behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return PlatformDomain.MARKET_EVENTS

    def collect_observations(self, context: AdapterContext) -> list[Observation]:
        """Collect observations for toolkit workflows.

        Args:
            context: Value supplied by the caller for context.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May read local system, file, or network state through configured providers.
        """
        event_id = context.payload.get("event_id", "CPI_2026_06")
        calendar_path = context.fixture_path or None
        event = get_event(event_id, Path(calendar_path) if calendar_path else None)
        return [
            Observation(
                domain=self.domain.value,
                signal="calendar_event",
                value=event.event_id,
                confidence=event.confidence,
                source_ref=event.source or "missing_source",
            ),
            Observation(
                domain=self.domain.value,
                signal="expected_volatility",
                value=event.expected_volatility.value,
                confidence=0.7,
            ),
            Observation(
                domain=self.domain.value,
                signal="direction_bias",
                value=event.direction_bias.value,
                confidence=0.6,
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
            weight = 0.65 if obs.signal == "calendar_event" else 0.5
            supports = True
            if obs.signal == "calendar_event" and obs.source_ref in ("", "missing_source"):
                supports = False
            evidence.append(
                Evidence(
                    evidence_id=f"mkt_{obs.signal}",
                    domain=self.domain.value,
                    label=f"{obs.signal}={obs.value}",
                    kind="observation",
                    weight=weight,
                    supports_decision=supports,
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
        event_id = context.payload.get("event_id", "CPI_2026_06")
        return [
            {
                "decision_id": f"mkt_thesis_{event_id}",
                "label": f"Publish research thesis for {event_id}",
                "base_benefit": 55.0,
                "base_risk": 20.0,
            },
            {
                "decision_id": f"mkt_monitor_{event_id}",
                "label": f"Monitor only — {event_id}",
                "base_benefit": 35.0,
                "base_risk": 8.0,
            },
        ]
