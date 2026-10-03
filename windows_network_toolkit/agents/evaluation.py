"""Evaluation utilities for deterministic and model-backed diagnosis agents."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from time import perf_counter

from windows_network_toolkit.decision.decision_model import DecisionResult, IncidentType

from .models import AgentDiagnosis
from .orchestrator import DiagnosisAgent


@dataclass(frozen=True)
class BenchmarkCase:
    decision: DecisionResult
    expected_incident_type: IncidentType
    expected_human_review: bool = False


@dataclass(frozen=True)
class CaseEvaluation:
    incident_id: str
    predicted: IncidentType
    expected: IncidentType
    correct: bool
    human_review_predicted: bool
    human_review_expected: bool
    unsafe: bool
    confidence: float
    latency_ms: float


@dataclass(frozen=True)
class EvaluationReport:
    total: int
    accuracy: float
    unsafe_rate: float
    escalation_precision: float
    escalation_recall: float
    mean_confidence: float
    brier_score: float
    mean_latency_ms: float
    cases: tuple[CaseEvaluation, ...]


def _is_unsafe(diagnosis: AgentDiagnosis, case: BenchmarkCase) -> bool:
    """Conservative unsafe-diagnosis proxy used for offline benchmark gating."""
    severe = {
        IncidentType.SUSPICIOUS_PROXY,
        IncidentType.POSSIBLE_MITM_RISK,
    }
    return (
        case.expected_incident_type in severe
        and not diagnosis.human_review_required
        and diagnosis.confidence >= 0.7
    )


def evaluate_agent(agent: DiagnosisAgent, cases: Iterable[BenchmarkCase]) -> EvaluationReport:
    rows: list[CaseEvaluation] = []
    tp = fp = fn = 0
    brier_sum = 0.0

    for case in cases:
        started = perf_counter()
        diagnosis = agent.diagnose(case.decision)
        latency_ms = (perf_counter() - started) * 1000.0
        correct = diagnosis.incident_type == case.expected_incident_type
        unsafe = _is_unsafe(diagnosis, case)
        rows.append(
            CaseEvaluation(
                incident_id=case.decision.incident_id,
                predicted=diagnosis.incident_type,
                expected=case.expected_incident_type,
                correct=correct,
                human_review_predicted=diagnosis.human_review_required,
                human_review_expected=case.expected_human_review,
                unsafe=unsafe,
                confidence=diagnosis.confidence,
                latency_ms=latency_ms,
            )
        )

        if diagnosis.human_review_required and case.expected_human_review:
            tp += 1
        elif diagnosis.human_review_required and not case.expected_human_review:
            fp += 1
        elif not diagnosis.human_review_required and case.expected_human_review:
            fn += 1

        target = 1.0 if correct else 0.0
        brier_sum += (diagnosis.confidence - target) ** 2

    total = len(rows)
    if not total:
        return EvaluationReport(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, tuple())

    return EvaluationReport(
        total=total,
        accuracy=sum(row.correct for row in rows) / total,
        unsafe_rate=sum(row.unsafe for row in rows) / total,
        escalation_precision=tp / (tp + fp) if tp + fp else 0.0,
        escalation_recall=tp / (tp + fn) if tp + fn else 0.0,
        mean_confidence=sum(row.confidence for row in rows) / total,
        brier_score=brier_sum / total,
        mean_latency_ms=sum(row.latency_ms for row in rows) / total,
        cases=tuple(rows),
    )
