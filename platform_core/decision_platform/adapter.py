"""DomainAdapter interface — plug domain facts into the shared reasoning engine.

System placement:
    - Implemented by adapters in :mod:`platform_core.decision_platform.adapters`.
    - Resolved via :mod:`platform_core.decision_platform.registry`.
    - Delegates scoring to :func:`platform_core.decision_platform.reasoning.run_shared_reasoning`.

Pipeline stages (each adapter implements the first three)::

    collect_observations → derive_evidence → build_candidate_specs → evaluate()

Key invariants:
    - Adapters do not call subprocesses or mutate host state during ``evaluate()``.
    - Candidate specs must include at least one entry or ``evaluate()`` raises.
    - Evidence IDs referenced in ``evidence_relevance`` must match ``Evidence.evidence_id``.

Side effects:
    - None in the base ``evaluate()`` implementation (pure transformation + engine call).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from .models import DomainPipelineResult, Evidence, Observation, PlatformDomain


class AdapterContext(BaseModel):
    """Opaque context passed into domain adapters.

    Attributes:
        scenario_id: Logical scenario label for audit (default ``default``).
        payload: Domain-specific key/value inputs (CLI rows, API body, fixture fields).
        fixture_path: Optional filesystem path to a JSON/YAML fixture.

    Input assumptions:
        ``payload`` keys are adapter-specific; missing keys fall back to adapter defaults.
        ``fixture_path`` is read only when an adapter explicitly uses it (e.g. market calendar).
    """

    scenario_id: str = "default"
    payload: dict[str, Any] = Field(default_factory=dict)
    fixture_path: str = ""


class DomainAdapter(ABC):
    """Translate domain-specific inputs into the unified Observation → Decision pipeline.

    Subclasses implement observation collection, evidence derivation, and candidate specs.
    The default ``evaluate()`` wires those stages into the shared engine.

    Engineering Notes:
        Fixture-driven defaults keep CI deterministic without live probes. Production
        wiring (Phase 1 migration) should populate ``payload`` from real collectors
        without changing this interface.
    """

    @property
    @abstractmethod
    def domain(self) -> PlatformDomain:
        """Return the platform domain this adapter serves."""

    @abstractmethod
    def collect_observations(self, context: AdapterContext) -> list[Observation]:
        """Normalize domain inputs into :class:`Observation` rows.

        Args:
            context: Scenario payload and optional fixture path.

        Returns:
            Non-empty or empty list of observations (adapter-defined).
        """

    @abstractmethod
    def derive_evidence(self, observations: list[Observation]) -> list[Evidence]:
        """Derive weighted evidence nodes from observations.

        Args:
            observations: Output of :meth:`collect_observations`.

        Returns:
            Evidence list passed to the shared engine. Use stable ``evidence_id`` values
            when referenced by candidate relevance maps.
        """

    @abstractmethod
    def build_candidate_specs(self, context: AdapterContext) -> list[dict[str, Any]]:
        """Return candidate decision specs for the shared engine.

        Each spec dict supports keys: ``decision_id``, ``label``, ``base_benefit``,
        ``base_risk``, ``evidence_relevance``, ``risk_factors``.

        Returns:
            At least one candidate dict is required for ``evaluate()`` to succeed.

        Raises:
            ValueError: Implicitly when ``evaluate()`` receives an empty list.
        """

    def evaluate(self, context: AdapterContext) -> DomainPipelineResult:
        """Run Observation → Evidence → shared reasoning → Decision.

        Args:
            context: Adapter input context.

        Returns:
            Full pipeline result including ranked alternatives and ``engine_digest``.

        Raises:
            ValueError: When no candidate specs are produced.
        """
        from .reasoning import run_shared_reasoning

        observations = self.collect_observations(context)
        evidence = self.derive_evidence(observations)
        return run_shared_reasoning(
            domain=self.domain,
            observations=observations,
            evidence=evidence,
            candidate_specs=self.build_candidate_specs(context),
        )
