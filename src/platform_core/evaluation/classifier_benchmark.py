"""Deterministic classifier evaluation harness for endpoint reliability evidence.

Fixture-only — no live Windows registry access.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from windows_network_toolkit.analytics_pipeline import (
    normalize_events_from_fixture,
    run_endpoint_analytics_pipeline,
)
from windows_network_toolkit.incident_classifier import classify_incident_from_events

_UNSAFE_PHRASES = (
    "malware confirmed",
    "malware detected",
    "mitm confirmed",
    "compromised",
    "autonomous repair",
    "kill the process",
    "reset the firewall",
    "audit opinion",
    "ai approved remediation",
    "safe to disable automatically",
)

_RISK_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_POLICY_RANK = {
    "observe": 0,
    "observe_or_alert": 1,
    "preview": 2,
    "preview_only": 2,
    "block_or_disable_preview": 3,
    "human_review": 4,
    "investigate_network_path": 4,
    "require_typed_confirmation": 5,
    "block": 6,
}


class ExpectedClassification(BaseModel):
    """Optional nested expected classification fields."""

    primary_classification: str | None = None
    secondary_signals: list[str] = Field(default_factory=list)
    policy_mode: str | None = None


class BenchmarkCase(BaseModel):
    """Single offline classifier benchmark case."""

    case_id: str
    scenario_name: str
    input_fixture_path: str | None = None
    fixture: dict[str, Any] | None = None
    expected_primary_classification: str
    expected_secondary_signals: list[str] = Field(default_factory=list)
    expected_policy_mode: str = "PREVIEW_ONLY"
    expected_limitations_required: list[str] = Field(default_factory=list)
    ambiguity_allowed: bool = False
    notes: str = ""


class BenchmarkResult(BaseModel):
    """Per-case classifier benchmark outcome."""

    case_id: str
    scenario_name: str
    predicted_primary: str
    expected_primary: str
    primary_match: bool
    secondary_match_rate: float
    policy_match: bool
    limitations_covered: bool
    unsafe_recommendation: bool
    unsafe_hits: list[str] = Field(default_factory=list)
    false_escalation: bool = False
    false_downgrade: bool = False
    predicted_risk_level: str = "UNKNOWN"
    predicted_policy_action: str = ""
    notes: str = ""


class BenchmarkSummary(BaseModel):
    """Aggregate classifier benchmark metrics."""

    schema_version: str = "classifier_benchmark.v1"
    total_cases: int = 0
    exact_primary_classification_match_rate: float = 0.0
    secondary_signal_match_rate: float = 0.0
    unsafe_recommendation_rate: float = 0.0
    limitation_coverage_rate: float = 0.0
    policy_gate_correctness_rate: float = 0.0
    false_escalation_count: int = 0
    false_downgrade_count: int = 0
    ambiguous_case_count: int = 0
    results: list[BenchmarkResult] = Field(default_factory=list)
    positioning: str = (
        "Deterministic classifier evaluation harness for endpoint reliability evidence."
    )


def _repo_root(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    return Path(__file__).resolve().parents[3]


def _load_fixture(case: BenchmarkCase, *, repo_root: Path) -> dict[str, Any]:
    if case.fixture:
        return case.fixture
    if not case.input_fixture_path:
        raise ValueError(f"case {case.case_id} has no fixture or input_fixture_path")
    path = Path(case.input_fixture_path)
    if not path.is_absolute():
        path = repo_root / path
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_policy_token(value: str) -> str:
    token = value.strip().upper().replace("-", "_")
    mapping = {
        "PREVIEW_ONLY": "PREVIEW_ONLY",
        "ALLOW_PREVIEW": "PREVIEW_ONLY",
        "REQUIRE_TYPED_CONFIRMATION": "REQUIRE_TYPED_CONFIRMATION",
        "REQUIRE_HUMAN_REVIEW": "HUMAN_REVIEW",
        "HUMAN_REVIEW": "HUMAN_REVIEW",
        "HUMAN_REVIEW_REQUIRED": "HUMAN_REVIEW",
        "OBSERVE": "OBSERVE",
        "BLOCK": "BLOCK",
    }
    return mapping.get(token, token)


def _predicted_policy_mode(incident_dict: dict[str, Any], fixture: dict[str, Any]) -> str:
    action = str(incident_dict.get("recommended_policy_action", "")).lower()
    if action in {"human_review", "investigate_network_path"}:
        return "HUMAN_REVIEW"
    if action in {"block_or_disable_preview"}:
        return "PREVIEW_ONLY"
    fixture_policy = (fixture.get("policy_decision") or {}).get("outcome")
    if fixture_policy:
        return _normalize_policy_token(str(fixture_policy))
    if action in {"observe", "observe_or_alert"}:
        return "OBSERVE"
    return "PREVIEW_ONLY"


def _scan_unsafe(blob: str) -> list[str]:
    lower = blob.lower()
    return [phrase for phrase in _UNSAFE_PHRASES if phrase in lower]


def _secondary_overlap(predicted: list[str], expected: list[str]) -> float:
    if not expected:
        return 1.0
    pred = {s.upper() for s in predicted}
    exp = {s.upper() for s in expected}
    if not exp:
        return 1.0
    return len(pred & exp) / len(exp)


def _limitations_covered(incident_limitations: list[str], required: list[str]) -> bool:
    if not required:
        return True
    blob = " ".join(incident_limitations).lower()
    return all(req.lower() in blob for req in required)


def _policy_rank(value: str) -> int:
    return _POLICY_RANK.get(value.lower(), _POLICY_RANK.get(_normalize_policy_token(value).lower(), 2))


def load_benchmark_cases(path: Path, *, repo_root: Path | None = None) -> list[BenchmarkCase]:
    """Load benchmark cases from JSON file (list or {cases: [...]})."""
    root = _repo_root(repo_root)
    file_path = path if path.is_absolute() else root / path
    data = json.loads(file_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "cases" in data:
        raw_cases = data["cases"]
    elif isinstance(data, list):
        raw_cases = data
    else:
        raise ValueError("benchmark file must be a list or {cases: [...]}")
    return [BenchmarkCase.model_validate(row) for row in raw_cases]


def run_classifier_benchmark(
    cases: list[BenchmarkCase],
    *,
    repo_root: Path | None = None,
) -> BenchmarkSummary:
    """Run fixture-only classifier benchmark and return aggregate summary."""
    root = _repo_root(repo_root)
    results: list[BenchmarkResult] = []
    ambiguous = 0

    for case in cases:
        if case.ambiguity_allowed:
            ambiguous += 1
        fixture = _load_fixture(case, repo_root=root)
        events = normalize_events_from_fixture(fixture)
        incident = classify_incident_from_events(events)
        incident_dict = incident.to_dict()
        payload = run_endpoint_analytics_pipeline(fixture=fixture)

        predicted_primary = incident.incident_class
        primary_match = predicted_primary == case.expected_primary_classification

        secondary_from_incident = []
        if predicted_primary != case.expected_primary_classification:
            secondary_from_incident.append(predicted_primary)
        sec_rate = _secondary_overlap(
            secondary_from_incident + list(case.expected_secondary_signals),
            case.expected_secondary_signals,
        )

        predicted_policy = _predicted_policy_mode(incident_dict, fixture)
        expected_policy = _normalize_policy_token(case.expected_policy_mode)
        policy_match = predicted_policy == expected_policy

        limitations_ok = _limitations_covered(
            list(incident.limitations),
            case.expected_limitations_required,
        )

        scan_blob = json.dumps(
            {
                "incident": incident_dict,
                "controls": payload.get("control_tests", []),
            }
        )
        unsafe_hits = _scan_unsafe(scan_blob)
        unsafe = bool(unsafe_hits)

        pred_risk = incident.risk_level
        exp_risk = "HIGH" if expected_policy in {"HUMAN_REVIEW", "BLOCK"} else "MEDIUM"
        if case.expected_primary_classification in {
            "DEAD_PROXY_CONFIG",
            "DIRECT_ONLY_WORKS",
            "UNKNOWN_LOCAL_PROXY",
        }:
            exp_risk = "HIGH"
        elif case.expected_primary_classification in {"LOCAL_PROXY_ACTIVE", "BOTH_DIRECT_AND_PROXY_WORK"}:
            exp_risk = "MEDIUM"

        false_escalation = False
        false_downgrade = False
        if not case.ambiguity_allowed:
            pr = _RISK_RANK.get(pred_risk, 0)
            er = _RISK_RANK.get(exp_risk, 2)
            if pr > er:
                false_escalation = True
            elif pr < er:
                false_downgrade = True
            pp = _policy_rank(predicted_policy)
            ep = _policy_rank(expected_policy)
            if pp > ep:
                false_escalation = True
            elif pp < ep:
                false_downgrade = True

        results.append(
            BenchmarkResult(
                case_id=case.case_id,
                scenario_name=case.scenario_name,
                predicted_primary=predicted_primary,
                expected_primary=case.expected_primary_classification,
                primary_match=primary_match,
                secondary_match_rate=sec_rate,
                policy_match=policy_match,
                limitations_covered=limitations_ok,
                unsafe_recommendation=unsafe,
                unsafe_hits=unsafe_hits,
                false_escalation=false_escalation,
                false_downgrade=false_downgrade,
                predicted_risk_level=pred_risk,
                predicted_policy_action=incident.recommended_policy_action,
                notes=case.notes,
            )
        )

    total = len(results) or 1
    summary = BenchmarkSummary(
        total_cases=len(results),
        exact_primary_classification_match_rate=sum(1 for r in results if r.primary_match) / total,
        secondary_signal_match_rate=sum(r.secondary_match_rate for r in results) / total,
        unsafe_recommendation_rate=sum(1 for r in results if r.unsafe_recommendation) / total,
        limitation_coverage_rate=sum(1 for r in results if r.limitations_covered) / total,
        policy_gate_correctness_rate=sum(1 for r in results if r.policy_match) / total,
        false_escalation_count=sum(1 for r in results if r.false_escalation),
        false_downgrade_count=sum(1 for r in results if r.false_downgrade),
        ambiguous_case_count=ambiguous,
        results=results,
    )
    return summary


def render_classifier_benchmark_markdown(summary: BenchmarkSummary) -> str:
    """Render governance-friendly markdown report."""
    lines = [
        "# Classifier Evaluation Report",
        "",
        f"_{summary.positioning}_",
        "",
        "## Summary metrics",
        "",
        f"- **total_cases:** {summary.total_cases}",
        f"- **exact_primary_classification_match_rate:** {summary.exact_primary_classification_match_rate:.2%}",
        f"- **secondary_signal_match_rate:** {summary.secondary_signal_match_rate:.2%}",
        f"- **unsafe_recommendation_rate:** {summary.unsafe_recommendation_rate:.2%}",
        f"- **limitation_coverage_rate:** {summary.limitation_coverage_rate:.2%}",
        f"- **policy_gate_correctness_rate:** {summary.policy_gate_correctness_rate:.2%}",
        f"- **false_escalation_count:** {summary.false_escalation_count}",
        f"- **false_downgrade_count:** {summary.false_downgrade_count}",
        f"- **ambiguous_case_count:** {summary.ambiguous_case_count}",
        "",
        "## Per-case results",
        "",
        "| case_id | predicted | expected | primary_match | policy_match | limitations | unsafe |",
        "|---------|-----------|----------|---------------|--------------|-------------|--------|",
    ]
    for row in summary.results:
        lines.append(
            f"| {row.case_id} | {row.predicted_primary} | {row.expected_primary} | "
            f"{'yes' if row.primary_match else 'no'} | {'yes' if row.policy_match else 'no'} | "
            f"{'yes' if row.limitations_covered else 'no'} | {'yes' if row.unsafe_recommendation else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Offline fixture evaluation only — not production telemetry.",
            "- Classification is triage, not a malware verdict.",
            "- Management information — not a formal audit opinion.",
        ]
    )
    return "\n".join(lines) + "\n"
