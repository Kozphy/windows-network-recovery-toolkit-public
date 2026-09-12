"""Unified cross-domain models for the Decision Intelligence Platform.

Pipeline contract shared by all domain adapters::

    Observation → Evidence → Decision → (optional) Outcome

System placement:
    - Consumed by :mod:`platform_core.decision_platform.adapter` and adapters.
    - Mapped from :mod:`src.decision_engine` output in :mod:`platform_core.decision_platform.reasoning`.
    - Distinct from :mod:`platform_core.decision_domain` (rich audit snapshots) and
      :mod:`platform_core.outcome_learning` (recorded ground-truth outcomes).

Key invariants:
    - ``confidence``, ``weight``, and score fields are bounded to documented ranges.
    - ``timestamp_utc`` / ``recorded_at_utc`` use UTC ISO-8601 via :func:`platform_core.models.utc_now_iso`.
    - Auto-generated IDs (``obs_*``, ``ev_*``, ``dec_*``) are unique per instance unless
      adapters set stable ``evidence_id`` values for replay determinism.

Output guarantees:
    - Models are JSON-serializable via Pydantic ``model_dump(mode="json")``.
    - No persistence side effects — adapters and API layers own storage.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso
from platform_core.reasoning_models import new_id


class PlatformDomain(StrEnum):
    """Registered platform domains resolved by :func:`platform_core.decision_platform.registry.get_adapter`."""

    WINDOWS = "windows"
    SECURITY = "security"
    CLOUD = "cloud"
    INFRASTRUCTURE = "infrastructure"
    MARKET_EVENTS = "market_events"


class Observation(BaseModel):
    """Raw or normalized fact collected by a domain adapter.

    Attributes:
        observation_id: Stable within a single pipeline run; auto-generated unless set.
        domain: Platform domain string (matches :class:`PlatformDomain` value).
        signal: Machine-readable signal name (e.g. ``proxy_enabled``, ``alert_severity``).
        value: Domain-specific payload (bool, str, float, etc.).
        confidence: Adapter-estimated confidence in the observation (0–1).
        source_ref: Provenance label (fixture path, probe name, SIEM ref).
        timestamp_utc: UTC ISO-8601 collection time.

    Notes:
        An observation is not proof — it is an input to evidence derivation.
    """

    observation_id: str = Field(default_factory=lambda: new_id("obs"))
    domain: str
    signal: str
    value: Any = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_ref: str = ""
    timestamp_utc: str = Field(default_factory=utc_now_iso)


class Evidence(BaseModel):
    """Weighted evidence node derived from one or more observations.

    Adapters should set stable ``evidence_id`` values when those IDs appear in
    candidate ``evidence_relevance`` maps passed to the shared engine.

    Attributes:
        evidence_id: Key used by :mod:`src.decision_engine` scoring relevance maps.
        kind: Semantic type (``observation``, ``inference``, ``counter_evidence``, ``proof``).
        weight: Influence on benefit/risk scoring (0–1).
        supports_decision: When False, contributes to risk rather than benefit.
        observation_ids: Back-links to contributing :class:`Observation` rows.
    """

    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    domain: str
    label: str
    kind: str = "observation"
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    supports_decision: bool = True
    detail: str = ""
    observation_ids: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    """Top-ranked recommendation produced by the shared reasoning engine.

    Attributes:
        title: Human-readable decision label (from engine candidate).
        benefit: Ordinal benefit score (0–100).
        risk: Ordinal risk score (0–100).
        final_score: ``clamp(round(benefit * confidence - risk * penalty), 0, 100)``.
        content_digest: SHA-256 replay anchor from engine output.
        recommendation: Short operator-facing guidance string.

    Audit Notes:
        Scores are research aids, not calibrated probabilities. Verify via
        ``engine_digest`` replay before changing scoring constants.
    """

    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    domain: str
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    benefit: int = Field(ge=0, le=100)
    risk: int = Field(ge=0, le=100)
    final_score: int = Field(ge=0, le=100)
    recommendation: str = ""
    content_digest: str = ""
    timestamp_utc: str = Field(default_factory=utc_now_iso)


class Outcome(BaseModel):
    """Optional recorded ground-truth outcome for learning loops.

    Distinct from :class:`platform_core.outcome_learning.models.DecisionOutcome`
    (same semantics, different module) and from expected outcomes on decision snapshots.
    """

    outcome_id: str = Field(default_factory=lambda: new_id("oc"))
    decision_id: str
    domain: str
    label: str
    success: bool
    predicted_success: bool = True
    notes: str = ""
    recorded_at_utc: str = Field(default_factory=utc_now_iso)


class DomainPipelineResult(BaseModel):
    """Common adapter output consumed by API handlers, audit, and replay.

    Attributes:
        alternatives: Ranked counterfactual paths from the shared engine.
        engine_digest: SHA-256 over evidence + ranked payload (replay anchor).

    Output guarantees:
        ``decision`` is always populated when ``evaluate()`` completes without error.
        ``outcome`` is None until an external learning loop records ground truth.
    """

    domain: str
    observations: list[Observation]
    evidence: list[Evidence]
    decision: Decision
    outcome: Outcome | None = None
    alternatives: list[dict[str, Any]] = Field(default_factory=list)
    engine_digest: str = ""
