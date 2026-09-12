"""Typed technology risk scoring for the endpoint analytics pipeline.

Module responsibility:
    Convert classified incidents, proof tiers, and control-test posture into ordinal
    ``risk_score`` / ``risk_level`` outputs for governance dashboards and human review.

System placement:
    Called by ``analytics_pipeline.run_endpoint_analytics_pipeline`` and
    ``reporting.attach_risk_scores``. Distinct from ``src/platform_core/risk/risk_rating.py``,
    which scores fixture case studies for ``risk-assess`` / ``governance-report``.

Key invariants:
    * Scores are ordinal governance input — not statistical probabilities or malware verdicts.
    * ``human_review_recommended`` is set for HIGH scores or control FAIL aggregates.
    * Every ``RiskScoringResult`` includes mandatory ``limitations[]``.

Input assumptions:
    * ``evidence_quality`` is clamped to [0.0, 1.0] (classifier confidence).
    * ``proof_level`` accepts T0–T4 prefixes or enum values; unknown values map to UNKNOWN.
    * ``business_impact`` is one of low/medium/high/critical (unknown → medium weight).

Output guarantees:
    * ``risk_score`` in [0.0, 100.0]; ``risk_level`` in {LOW, MEDIUM, HIGH}.
    * ``explanation`` cites inputs used; ``limitations`` always non-empty.

Side effects:
    None — pure functions.

Idempotency:
    Deterministic for identical inputs.

Failure modes:
    Missing incident fields default to UNKNOWN class and 0.5 evidence quality.
    Empty control list aggregates to NOT_TESTED.

Audit Notes:
    * Mis-scoring from stale or incomplete audit JSONL is possible — verify ``limitations[]``
      and proof tier before escalation.
    * Recovery: re-run pipeline from fresh ``proxy-watch`` / ``proxy-health`` evidence;
      collect T4 writer proof before treating HIGH as actionable.

Engineering Notes:
    Keeps scoring separate from ``incident_classifier.risk_level`` (fast triage label) so
    API/CLI consumers can evolve scoring weights without changing classification labels.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

GOVERNANCE_LIMITATIONS = [
    "Risk score is ordinal governance input, not a statistical probability.",
    "Correlation and listener attribution do not prove registry writer identity without T4 proof.",
    "Classification is not accusation — this is not malware or EDR verdicting.",
    "Policy permission is not a safety guarantee; human review may still be required.",
]


class ProofLevel(StrEnum):
    """Evidence proof tier mapped to scoring weight.

    Aligns with analytics ``EvidenceTier`` labels (T0–T4). Used only inside scoring math;
    does not upgrade claim strength in stored evidence.
    """

    T0_OBSERVATION = "T0"
    T1_CORRELATION = "T1"
    T2_SUPPORTED = "T2"
    T3_STRONG = "T3"
    T4_WRITER_PROOF = "T4"
    NOT_RUN = "NOT_RUN"
    UNKNOWN = "UNKNOWN"


class ControlAggregate(StrEnum):
    """Worst-case control outcome used when multiple tests apply to one incident."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_TESTED = "NOT_TESTED"


_PROOF_WEIGHT: dict[str, float] = {
    ProofLevel.T0_OBSERVATION.value: 0.15,
    ProofLevel.T1_CORRELATION.value: 0.35,
    ProofLevel.T2_SUPPORTED.value: 0.55,
    ProofLevel.T3_STRONG.value: 0.75,
    ProofLevel.T4_WRITER_PROOF.value: 0.9,
    ProofLevel.NOT_RUN.value: 0.1,
    ProofLevel.UNKNOWN.value: 0.2,
}

_IMPACT_SCORE: dict[str, float] = {"low": 1.0, "medium": 2.5, "high": 4.0, "critical": 5.0}

_HIGH_CLASSES = frozenset(
    {
        "REVERTER_SUSPECTED",
        "PROXY_FLAPPING",
        "POSSIBLE_MITM_RISK",
        "BOTH_DIRECT_AND_PROXY_FAIL",
        "DEAD_PROXY_CONFIG",
    }
)
_MEDIUM_CLASSES = frozenset(
    {
        "LOCAL_PROXY_ACTIVE",
        "UNKNOWN_LOCAL_PROXY",
        "WININET_WINHTTP_MISMATCH",
        "DIRECT_ONLY_WORKS",
        "STALE_PROXY_AFTER_PROCESS_EXIT",
    }
)

_CONTROL_MODIFIER: dict[str, float] = {
    ControlAggregate.PASS.value: -0.15,
    ControlAggregate.PARTIAL.value: 0.05,
    ControlAggregate.FAIL.value: 0.25,
    ControlAggregate.NOT_TESTED.value: 0.1,
}


@dataclass
class RiskScoringInput:
    """Inputs for ordinal risk scoring.

    Attributes:
        incident_class: Primary classification label from ``incident_classifier``.
        evidence_quality: Classifier confidence in [0.0, 1.0]; clamped in ``__post_init__``.
        proof_level: T0–T4 tier string or enum value.
        business_impact: Impact band: low, medium, high, or critical.
        recurrence_count: Repeat observations in audit window (non-negative).
        control_test_result: Worst-case aggregate control outcome string.
    """

    incident_class: str
    evidence_quality: float
    proof_level: str
    business_impact: str
    recurrence_count: int = 0
    control_test_result: str = ControlAggregate.NOT_TESTED.value

    def __post_init__(self) -> None:
        self.evidence_quality = max(0.0, min(1.0, float(self.evidence_quality)))
        self.recurrence_count = max(0, int(self.recurrence_count))


@dataclass
class RiskScoringResult:
    """Ordinal risk scoring output for one incident.

    Attributes:
        likelihood: low, medium, or high — ordinal, not probability.
        impact: Business impact band echoed from input.
        risk_score: Composite 0–100 for sorting and dashboards.
        risk_level: LOW, MEDIUM, or HIGH bucket.
        explanation: Human-readable rationale citing inputs.
        limitations: Governance caveats; always populated.
        incident_class: Echo of classified incident label.
        human_review_recommended: True when escalation to analyst is advised.
    """

    likelihood: str
    impact: str
    risk_score: float
    risk_level: str
    explanation: str
    limitations: list[str] = field(default_factory=list)
    incident_class: str = ""
    human_review_recommended: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize result for JSON export and API responses."""
        return asdict(self)


def _normalize_proof_level(proof_level: str) -> str:
    raw = (proof_level or ProofLevel.UNKNOWN.value).upper()
    if raw.startswith("T4"):
        return ProofLevel.T4_WRITER_PROOF.value
    if raw.startswith("T3"):
        return ProofLevel.T3_STRONG.value
    if raw.startswith("T2"):
        return ProofLevel.T2_SUPPORTED.value
    if raw.startswith("T1"):
        return ProofLevel.T1_CORRELATION.value
    if raw.startswith("T0"):
        return ProofLevel.T0_OBSERVATION.value
    if raw in {p.value for p in ProofLevel}:
        return raw
    return ProofLevel.UNKNOWN.value


def _class_likelihood_base(incident_class: str) -> float:
    if incident_class in _HIGH_CLASSES:
        return 0.75
    if incident_class in _MEDIUM_CLASSES:
        return 0.5
    if incident_class in ("NO_PROXY", "BOTH_DIRECT_AND_PROXY_WORK", "PROXY_ONLY_WORKS"):
        return 0.2
    return 0.35


def _score_to_level(score: float) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _likelihood_label(score: float) -> str:
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def score_risk(inputs: RiskScoringInput) -> RiskScoringResult:
    """Compute ordinal risk score from incident evidence and control posture.

    Args:
        inputs: Validated scoring inputs; ``evidence_quality`` and ``recurrence_count``
            are clamped in ``RiskScoringInput.__post_init__``.

    Returns:
        RiskScoringResult with likelihood, impact, risk_score, risk_level, explanation,
        limitations, and human_review_recommended flag.

    Side effects:
        None.

    Audit Notes:
        HIGH scores with T0/T1 proof should not authorize remediation without human review.
        Verify control_test_result against raw ``control_tests[]`` before committee reporting.
    """
    proof_key = _normalize_proof_level(inputs.proof_level)
    proof_weight = _PROOF_WEIGHT.get(proof_key, 0.2)

    class_base = _class_likelihood_base(inputs.incident_class)
    recurrence_boost = min(0.2, inputs.recurrence_count * 0.05)
    likelihood_raw = min(
        1.0,
        (class_base * 0.45)
        + (inputs.evidence_quality * 0.25)
        + (proof_weight * 0.2)
        + recurrence_boost
        + _CONTROL_MODIFIER.get(inputs.control_test_result, 0.1),
    )

    impact_key = (inputs.business_impact or "medium").lower()
    impact_score = _IMPACT_SCORE.get(impact_key, 2.5)

    risk_score = round(min(100.0, likelihood_raw * impact_score * 20.0), 1)
    risk_level = _score_to_level(risk_score)
    likelihood = _likelihood_label(likelihood_raw)
    impact = impact_key if impact_key in _IMPACT_SCORE else "medium"

    limitations = list(GOVERNANCE_LIMITATIONS)
    if proof_key in (ProofLevel.T0_OBSERVATION.value, ProofLevel.T1_CORRELATION.value, ProofLevel.UNKNOWN.value):
        limitations.append("Proof tier is observation or correlation — escalate only with additional validation.")
    if inputs.control_test_result == ControlAggregate.NOT_TESTED.value:
        limitations.append("One or more controls were NOT_TESTED; residual risk may be understated.")
    if inputs.recurrence_count >= 3:
        limitations.append("Recurrence pattern observed — review change management and writer attribution.")

    human_review = risk_level == "HIGH" or inputs.control_test_result == ControlAggregate.FAIL.value

    explanation = (
        f"Incident class {inputs.incident_class} with {likelihood} likelihood and {impact} impact "
        f"(evidence_quality={inputs.evidence_quality:.2f}, proof={proof_key}, "
        f"controls={inputs.control_test_result}, recurrence={inputs.recurrence_count}) "
        f"yields risk_score={risk_score} ({risk_level})."
    )

    return RiskScoringResult(
        likelihood=likelihood,
        impact=impact,
        risk_score=risk_score,
        risk_level=risk_level,
        explanation=explanation,
        limitations=limitations,
        incident_class=inputs.incident_class,
        human_review_recommended=human_review,
    )


def aggregate_control_result(test_results: list[str]) -> str:
    """Return worst-case control outcome across multiple test result strings.

    Precedence (highest severity first): FAIL, PARTIAL, NOT_TESTED, PASS.

    Args:
        test_results: Raw ``test_result`` values from control test dicts or enums.

    Returns:
        One of PASS, FAIL, PARTIAL, NOT_TESTED. Defaults to NOT_TESTED when empty.
    """
    order = [
        ControlAggregate.FAIL.value,
        ControlAggregate.PARTIAL.value,
        ControlAggregate.NOT_TESTED.value,
        ControlAggregate.PASS.value,
    ]
    normalized = {(r or "").upper() for r in test_results}
    for outcome in order:
        if outcome in normalized:
            return outcome
    return ControlAggregate.NOT_TESTED.value


def score_risk_from_incident(
    incident: dict[str, Any],
    *,
    control_tests: list[dict[str, Any]] | None = None,
    proof_level: str | None = None,
    business_impact: str | None = None,
    recurrence_count: int = 0,
) -> RiskScoringResult:
    """Score risk from analytics pipeline incident and control test dicts.

    Args:
        incident: Incident dict from ``analytics_pipeline`` (requires ``incident_class``;
            optional ``incident_id``, ``confidence``, ``risk_level``).
        control_tests: Flat list of control test dicts; filtered by ``incident_id`` when set.
        proof_level: Override proof tier; inferred from control ``evidence_tier`` when omitted.
        business_impact: Override impact band; inferred from incident ``risk_level`` when omitted.
        recurrence_count: Repeat observation count for scoring boost.

    Returns:
        RiskScoringResult from ``score_risk``.

    Side effects:
        None.

    Data handling:
        Missing fields use UNKNOWN class, 0.5 confidence, T1 proof default, medium impact.
        Malformed ``test_result`` strings are uppercased; unknown values aggregate as NOT_TESTED.
    """
    incident_id = incident.get("incident_id", "")
    incident_class = str(incident.get("incident_class") or "UNKNOWN")
    evidence_quality = float(incident.get("confidence") or 0.5)

    related_controls = [
        c
        for c in (control_tests or [])
        if not incident_id or c.get("incident_id") in (incident_id, None, "")
    ]
    if not related_controls and control_tests:
        related_controls = control_tests

    control_agg = aggregate_control_result([str(c.get("test_result", "")) for c in related_controls])

    tier = proof_level
    if tier is None:
        tiers = [str(c.get("evidence_tier", "")) for c in related_controls if c.get("evidence_tier")]
        tier = max(tiers, default=ProofLevel.T1_CORRELATION.value) if tiers else ProofLevel.T1_CORRELATION.value

    biz = business_impact
    if biz is None:
        biz = "high" if incident.get("risk_level") == "HIGH" else "medium"

    return score_risk(
        RiskScoringInput(
            incident_class=incident_class,
            evidence_quality=evidence_quality,
            proof_level=str(tier),
            business_impact=str(biz),
            recurrence_count=recurrence_count,
            control_test_result=control_agg,
        )
    )
