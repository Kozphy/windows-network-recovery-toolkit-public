"""Structured investigation artifacts separating observation, inference, and proof.

Module responsibility:
    Define immutable-friendly dataclasses for a single proxy-drift investigation run:
    observations (facts), hypotheses (possible explanations), remediation previews,
    and serializable ``ProxyInvestigationResult`` rows for JSONL audit.

System placement:
    Consumed by ``workflow``, ``report``, and ``audit``. Does not perform I/O or subprocess
    execution.

Key invariants:
    * Hypotheses are ranked explanations, not proven root causes.
    * ``AttributionStatus`` never implies registry-writer proof unless extended upstream
      with verified telemetry (not modeled here as ``writer_proof`` by default).

Input assumptions:
    Callers populate fields from collectors and validation modules on Windows.

Output guarantees:
    ``ProxyInvestigationResult.to_jsonable()`` returns JSON-serializable dicts suitable for
    append-only logs under ``logs/proxy_investigation.jsonl``.

Side effects:
    None at import time; serialization allocates dict copies only.

Audit Notes:
    * Review ``attribution_status`` and ``limitations`` before sharing reports externally.
    * ``human_report`` may summarize sensitive process paths — treat like local forensic data.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

ConfidenceRank = Literal["low", "medium", "high"]
AttributionStatus = Literal["unknown", "listener_correlation", "writer_proof"]
PolicyOutcome = Literal["ALLOW", "PREVIEW", "BLOCK"]
VerificationStatus = Literal["UNVERIFIED", "INCONCLUSIVE", "CONFIRMED", "REJECTED"]


def new_run_id() -> str:
    """Generate a short investigation run identifier.

    Returns:
        String prefixed with ``inv_`` and a random hex suffix.
    """
    return f"inv_{uuid.uuid4().hex[:16]}"


@dataclass(frozen=True)
class Observation:
    """Raw measured fact from collectors or probes.

    Attributes:
        id: Stable observation key for cross-referencing in reports.
        category: Grouping such as ``registry``, ``listener``, ``probe``.
        summary: One-line operator-facing fact (no inference verbs).
        detail: Structured payload for replay and JSONL audit.
    """

    id: str
    category: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Hypothesis:
    """Possible explanation for symptoms — not a proven fact.

    Attributes:
        hypothesis_id: Machine-readable scenario key.
        title: Short human title using cautious language.
        confidence: Ordinal rank (``low`` | ``medium`` | ``high``), not probability.
        evidence_for: Observation-derived bullets supporting the story.
        evidence_against: Bullets that weaken or contradict the story.
        limitations: Epistemic boundaries for this hypothesis.
    """

    hypothesis_id: str
    title: str
    confidence: ConfidenceRank
    evidence_for: tuple[str, ...]
    evidence_against: tuple[str, ...]
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemediationPreview:
    """Preview-only remediation row; never auto-executed from this workflow.

    Attributes:
        action_id: Allowlisted action token consumed by policy surfaces.
        title: Operator-facing action name.
        policy: ``ALLOW``, ``PREVIEW``, or ``BLOCK`` for this workflow's catalog.
        detail: Explanation of scope and confirmation requirements.
        command_preview: Optional example CLI or shell snippet (informational only).
    """

    action_id: str
    title: str
    policy: PolicyOutcome
    detail: str
    command_preview: str | None = None


@dataclass
class ProxyInvestigationResult:
    """Full replayable proxy drift investigation run.

    Attributes:
        run_id: Unique investigation identifier.
        timestamp: UTC ISO-8601 capture time from caller.
        schema_version: Audit schema token for forward-compatible readers.
        proxy_snapshot: WinINET/WinHTTP/env/npm/git proxy surfaces.
        listener_evidence: Localhost listener and process inventory block.
        dev_process_evidence: Node/Electron/dev-tool correlation rows.
        validation: DNS/TCP/HTTPS and contrast probe summary.
        path_assessment: Optional ``assess_proxy_path_operational`` JSON.
        observations: Flattened observation list for reports.
        hypotheses: Ranked hypothesis list (index 0 is primary).
        competing_hypotheses: Deprioritized scenario ids.
        primary_hypothesis_id: ``hypotheses[0].hypothesis_id`` when non-empty.
        confidence_boundary: Ordinal cap explanation for primary hypothesis.
        verification_strategy: Suggested follow-up checks for operators.
        attribution_status: ``unknown`` | ``listener_correlation`` | ``writer_proof``.
        attribution_notes: Human-readable attribution boundaries.
        risk_assessment: Operational risk summary dict.
        remediation_previews: Preview catalog rows.
        limitations: Global investigation limitations.
        human_report: Rendered markdown incident report.
        before_snapshot: Optional prior proxy snapshot for drift context.
    """

    run_id: str
    timestamp: str
    schema_version: str
    proxy_snapshot: dict[str, Any]
    listener_evidence: dict[str, Any]
    dev_process_evidence: dict[str, Any]
    validation: dict[str, Any]
    path_assessment: dict[str, Any] | None
    observations: list[Observation]
    hypotheses: list[Hypothesis]
    competing_hypotheses: list[str]
    primary_hypothesis_id: str
    confidence_boundary: str
    verification_strategy: list[str]
    attribution_status: AttributionStatus
    attribution_notes: list[str]
    risk_assessment: dict[str, Any]
    remediation_previews: list[RemediationPreview]
    limitations: list[str]
    human_report: str
    before_snapshot: dict[str, Any] | None = None

    def to_jsonable(self) -> dict[str, Any]:
        """Serialize the investigation run for append-only JSONL audit.

        Returns:
            Dictionary with ``record_type=proxy_investigation`` and nested evidence blobs.

        Side effects:
            Allocates new dict/list structures only.
        """
        return {
            "record_type": "proxy_investigation",
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "before_snapshot": self.before_snapshot,
            "proxy_snapshot": self.proxy_snapshot,
            "listener_evidence": self.listener_evidence,
            "dev_process_evidence": self.dev_process_evidence,
            "validation": self.validation,
            "path_assessment": self.path_assessment,
            "observations": [
                {"id": o.id, "category": o.category, "summary": o.summary, "detail": o.detail}
                for o in self.observations
            ],
            "hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "title": h.title,
                    "confidence": h.confidence,
                    "evidence_for": list(h.evidence_for),
                    "evidence_against": list(h.evidence_against),
                    "limitations": list(h.limitations),
                }
                for h in self.hypotheses
            ],
            "competing_hypotheses": self.competing_hypotheses,
            "primary_hypothesis_id": self.primary_hypothesis_id,
            "confidence_boundary": self.confidence_boundary,
            "verification_strategy": self.verification_strategy,
            "attribution_status": self.attribution_status,
            "attribution_notes": self.attribution_notes,
            "risk_assessment": self.risk_assessment,
            "remediation_previews": [
                {
                    "action_id": r.action_id,
                    "title": r.title,
                    "policy": r.policy,
                    "detail": r.detail,
                    "command_preview": r.command_preview,
                }
                for r in self.remediation_previews
            ],
            "limitations": self.limitations,
        }
