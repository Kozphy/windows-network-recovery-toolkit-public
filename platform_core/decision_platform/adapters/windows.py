"""Windows domain adapter — endpoint proxy and network reliability.

Maps WinINET proxy drift, DNS health, and listener correlation signals into the
shared decision engine. Defaults are fixture-friendly for CI; production wiring
should populate ``AdapterContext.payload`` from ``python -m src`` collectors.

Key invariants:
    - Stable ``evidence_id`` values (``proxy_enabled``, ``listener_on_proxy_port``)
      align with candidate ``evidence_relevance`` maps.
    - Counter-evidence ``no_writer_proof`` is injected when Sysmon writer proof is absent.

Audit Notes:
    Listener correlation is not registry-writer proof. Decisions remain preview-gated
    by the existing Windows toolkit policy layer — this adapter does not execute remediation.
"""

from __future__ import annotations

from typing import Any

from ..adapter import AdapterContext, DomainAdapter
from ..models import Evidence, Observation, PlatformDomain


class WindowsAdapter(DomainAdapter):
    """Adapter for Windows endpoint reliability (proxy/DNS/listener signals)."""

    @property
    def domain(self) -> PlatformDomain:
        """Provide domain behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return PlatformDomain.WINDOWS

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
                signal="proxy_enabled",
                value=payload.get("proxy_enabled", True),
                confidence=0.85,
                source_ref=payload.get("source_ref", "fixture:wininet"),
            ),
            Observation(
                domain=self.domain.value,
                signal="dns_ok",
                value=payload.get("dns_ok", True),
                confidence=0.9,
                source_ref="fixture:dns_probe",
            ),
            Observation(
                domain=self.domain.value,
                signal="listener_on_proxy_port",
                value=payload.get("listener_match", True),
                confidence=0.6,
                source_ref="fixture:listener_correlation",
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
            if obs.signal == "no_writer_proof":
                continue
            if obs.signal == "proxy_enabled" and obs.value:
                evidence.append(
                    Evidence(
                        evidence_id="proxy_enabled",
                        domain=self.domain.value,
                        label="ProxyEnable observed in user profile",
                        kind="observation",
                        weight=0.8,
                        supports_decision=True,
                        detail=str(obs.value),
                        observation_ids=[obs.observation_id],
                    )
                )
            elif obs.signal == "listener_on_proxy_port" and obs.value:
                evidence.append(
                    Evidence(
                        evidence_id="listener_on_proxy_port",
                        domain=self.domain.value,
                        label="Local listener correlates with proxy port",
                        kind="inference",
                        weight=0.55,
                        supports_decision=True,
                        detail="Correlation is not registry-writer proof",
                        observation_ids=[obs.observation_id],
                    )
                )
            elif obs.signal == "dns_ok":
                evidence.append(
                    Evidence(
                        evidence_id="dns_ok",
                        domain=self.domain.value,
                        label="DNS resolution healthy",
                        kind="observation",
                        weight=0.4,
                        supports_decision=bool(obs.value),
                        observation_ids=[obs.observation_id],
                    )
                )
        if not any(e.label.startswith("No writer") for e in evidence):
            evidence.append(
                Evidence(
                    evidence_id="no_writer_proof",
                    domain=self.domain.value,
                    label="No registry writer proof in context",
                    kind="counter_evidence",
                    weight=0.5,
                    supports_decision=False,
                    detail="Sysmon Event 13 not attached",
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
                "decision_id": "win_preview_disable_proxy",
                "label": "Preview disable WinINET proxy",
                "base_benefit": 58.0,
                "base_risk": 22.0,
                "evidence_relevance": {
                    "proxy_enabled": 1.0,
                    "listener_on_proxy_port": 0.8,
                },
                "risk_factors": {"registry_mutation": 12.0},
            },
            {
                "decision_id": "win_monitor_only",
                "label": "Continue monitoring",
                "base_benefit": 32.0,
                "base_risk": 8.0,
                "evidence_relevance": {"proxy_enabled": 0.4},
            },
        ]
