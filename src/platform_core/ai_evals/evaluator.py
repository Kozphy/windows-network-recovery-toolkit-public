"""Deterministic fixture-based AI eval evaluator.

Loads JSON fixture cases, runs heuristic checks against embedded ``model_output`` fields,
and aggregates pass/fail/partial status with failure taxonomy labels.

No live LLM or retrieval API calls are made. Checks include exact match, required facts,
unsupported claims, JSON format, citations, refusal detection, safety phrases, and
latency/cost thresholds.

Functions:
    load_eval_cases: Parse a fixture JSON file into ``EvalCase`` instances.
    evaluate_case: Run all checks on a single case.
    run_eval_suite: Evaluate a list of cases and build an ``EvalReport``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .failure_taxonomy import (
    BASELINE_LIMITATIONS,
    REFUSAL_PHRASES,
    UNSAFE_PHRASES,
    EvalPolicyGate,
    FailureLabel,
)
from .policy import evaluate_eval_policy
from .schemas import (
    ConfidenceLevel,
    EvalCase,
    EvalReport,
    EvalResult,
    EvalStatus,
    FailureSignal,
    ModelOutput,
)


def _normalize(text: str) -> str:
    return " ".join(text.split()).strip().lower()


def _output_text(case: EvalCase) -> str:
    return case.model_output.text or ""


def _evidence_corpus(case: EvalCase) -> str:
    parts = list(case.retrieved_context) + list(case.expected_facts)
    return " ".join(parts).lower()


def check_exact_match(case: EvalCase) -> tuple[bool, dict[str, Any]]:
    """Return check exact match.

    Args:
        case: case supplied by the caller.

    Returns:
        The computed `tuple[bool, dict[str, Any]]` value.

    Side effects:
        None.
    """
    if not case.expected_answer:
        return True, {"exact_match": None, "skipped": True}
    actual = _normalize(_output_text(case))
    expected = _normalize(case.expected_answer)
    ok = actual == expected
    return ok, {"exact_match": ok, "expected": case.expected_answer}


def check_required_facts(case: EvalCase) -> tuple[bool, dict[str, Any], list[FailureSignal]]:
    """Return check required facts.

    Args:
        case: case supplied by the caller.

    Returns:
        The computed `tuple[bool, dict[str, Any], list[FailureSignal]]` value.

    Side effects:
        None.
    """
    if not case.expected_facts:
        return True, {"facts_found": 0, "facts_required": 0}, []
    text = _output_text(case).lower()
    missing = [fact for fact in case.expected_facts if fact.lower() not in text]
    found = len(case.expected_facts) - len(missing)
    signals: list[FailureSignal] = []
    if missing:
        signals.append(
            FailureSignal(
                label=FailureLabel.RETRIEVAL_MISS,
                detail=f"Missing required facts: {', '.join(missing)}",
                severity="medium",
            )
        )
    return (
        len(missing) == 0,
        {
            "facts_found": found,
            "facts_required": len(case.expected_facts),
            "missing_facts": missing,
        },
        signals,
    )


def check_unsupported_claims(case: EvalCase) -> tuple[bool, dict[str, Any], list[FailureSignal]]:
    """Approximate unsupported-claim detection via sentence heuristics."""
    if not case.retrieved_context and not case.expected_facts:
        return True, {"unsupported_claim_check": "skipped"}, []

    corpus = _evidence_corpus(case)
    text = _output_text(case)
    sentences = [s.strip() for s in re.split(r"[.!?\n]+", text) if s.strip()]
    unsupported: list[str] = []
    for sentence in sentences:
        norm = sentence.lower()
        if len(norm) < 12:
            continue
        if any(phrase in norm for phrase in REFUSAL_PHRASES):
            continue
        tokens = [t for t in re.findall(r"[a-z0-9]+", norm) if len(t) > 4]
        if not tokens:
            continue
        overlap = sum(1 for t in tokens if t in corpus)
        if overlap == 0 and norm not in corpus:
            unsupported.append(sentence)

    signals: list[FailureSignal] = []
    if unsupported:
        signals.append(
            FailureSignal(
                label=FailureLabel.UNSUPPORTED_CLAIM,
                detail=f"Unsupported statements: {unsupported[0][:120]}",
                severity="medium",
            )
        )
        if len(unsupported) > 1:
            signals.append(
                FailureSignal(
                    label=FailureLabel.HALLUCINATION_RISK,
                    detail="Multiple statements lack grounding in retrieved context.",
                    severity=case.severity,
                )
            )
    return len(unsupported) == 0, {"unsupported_sentences": unsupported}, signals


def check_format_json(case: EvalCase) -> tuple[bool, dict[str, Any], list[FailureSignal]]:
    """Return check format json.

    Args:
        case: case supplied by the caller.

    Returns:
        The computed `tuple[bool, dict[str, Any], list[FailureSignal]]` value.

    Side effects:
        None.
    """
    if case.format_spec != "json":
        return True, {"format_check": "skipped"}, []

    payload = case.model_output.json_payload
    if payload is not None:
        return True, {"format_check": "json_payload_valid"}, []

    text = _output_text(case)
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return (
            False,
            {"format_check": "no_json_found"},
            [
                FailureSignal(
                    label=FailureLabel.FORMAT_VIOLATION,
                    detail="Required JSON output not found.",
                    severity="medium",
                )
            ],
        )
    try:
        json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        return (
            False,
            {"format_check": "invalid_json", "error": str(exc)},
            [
                FailureSignal(
                    label=FailureLabel.FORMAT_VIOLATION,
                    detail=f"Invalid JSON: {exc}",
                    severity="medium",
                )
            ],
        )
    return True, {"format_check": "parsed_from_text"}, []


def check_citations(case: EvalCase) -> tuple[bool, dict[str, Any], list[FailureSignal]]:
    """Return check citations.

    Args:
        case: case supplied by the caller.

    Returns:
        The computed `tuple[bool, dict[str, Any], list[FailureSignal]]` value.

    Side effects:
        None.
    """
    if not case.require_citations:
        return True, {"citation_check": "skipped"}, []

    citations = case.model_output.citations
    text = _output_text(case)
    has_citation = bool(citations) or "[doc:" in text.lower() or "source:" in text.lower()
    if has_citation:
        return True, {"citation_check": "present", "citation_count": len(citations)}, []
    return (
        False,
        {"citation_check": "missing"},
        [
            FailureSignal(
                label=FailureLabel.INSUFFICIENT_EVIDENCE,
                detail="Required citations or source markers missing.",
                severity="medium",
            )
        ],
    )


def check_refusal(case: EvalCase) -> tuple[bool, dict[str, Any], list[FailureSignal]]:
    """Return check refusal.

    Args:
        case: case supplied by the caller.

    Returns:
        The computed `tuple[bool, dict[str, Any], list[FailureSignal]]` value.

    Side effects:
        None.
    """
    if case.expected_answer is None and not case.expected_facts:
        return True, {"refusal_check": "skipped"}, []

    text = _normalize(_output_text(case))
    if not text:
        return (
            False,
            {"refusal_check": "empty_output"},
            [
                FailureSignal(
                    label=FailureLabel.REFUSAL_UNEXPECTED,
                    detail="Empty output when answer expected.",
                    severity="medium",
                )
            ],
        )
    for phrase in REFUSAL_PHRASES:
        if phrase in text:
            return (
                False,
                {"refusal_check": "refusal_detected", "phrase": phrase},
                [
                    FailureSignal(
                        label=FailureLabel.REFUSAL_UNEXPECTED,
                        detail=f"Unexpected refusal phrase detected: {phrase}",
                        severity="medium",
                    )
                ],
            )
    return True, {"refusal_check": "ok"}, []


def check_safety_phrases(case: EvalCase) -> tuple[bool, dict[str, Any], list[FailureSignal]]:
    """Return check safety phrases.

    Args:
        case: case supplied by the caller.

    Returns:
        The computed `tuple[bool, dict[str, Any], list[FailureSignal]]` value.

    Side effects:
        None.
    """
    text = _output_text(case).lower()
    hits = [p for p in UNSAFE_PHRASES if p in text]
    if not hits:
        return True, {"unsafe_phrase_hits": []}, []
    return (
        False,
        {"unsafe_phrase_hits": hits},
        [
            FailureSignal(
                label=FailureLabel.SAFETY_REVIEW_REQUIRED,
                detail=f"Risky phrasing detected: {hits[0]}",
                severity="high",
            )
        ],
    )


def check_latency_cost(case: EvalCase) -> tuple[bool, dict[str, Any], list[FailureSignal]]:
    """Return check latency cost.

    Args:
        case: case supplied by the caller.

    Returns:
        The computed `tuple[bool, dict[str, Any], list[FailureSignal]]` value.

    Side effects:
        None.
    """
    out = case.model_output
    breached = False
    details: dict[str, Any] = {}
    if case.max_latency_ms is not None and out.latency_ms is not None:
        details["latency_ms"] = out.latency_ms
        details["max_latency_ms"] = case.max_latency_ms
        if out.latency_ms > case.max_latency_ms:
            breached = True
    if case.max_token_cost_usd is not None and out.token_cost_usd is not None:
        details["token_cost_usd"] = out.token_cost_usd
        details["max_token_cost_usd"] = case.max_token_cost_usd
        if out.token_cost_usd > case.max_token_cost_usd:
            breached = True
    if not breached:
        return True, details or {"latency_cost_check": "ok"}, []
    return (
        False,
        details,
        [
            FailureSignal(
                label=FailureLabel.LATENCY_OR_COST_REGRESSION,
                detail="Latency or cost exceeds configured threshold.",
                severity="low",
            )
        ],
    )


def _confidence_from_checks(passed: int, total: int) -> ConfidenceLevel:
    if total == 0:
        return "medium"
    ratio = passed / total
    if ratio >= 0.95:
        return "high"
    if ratio >= 0.75:
        return "medium"
    if ratio >= 0.5:
        return "low"
    return "very_low"


def evaluate_case(case: EvalCase) -> EvalResult:
    """Run deterministic checks on a single fixture case."""
    checks_run: list[str] = []
    metrics: dict[str, Any] = {}
    all_signals: list[FailureSignal] = []
    pass_count = 0
    total_checks = 0

    check_fns = [
        ("exact_match", lambda: check_exact_match(case)),
        ("required_facts", lambda: check_required_facts(case)),
        ("unsupported_claim", lambda: check_unsupported_claims(case)),
        ("format_json", lambda: check_format_json(case)),
        ("citation_presence", lambda: check_citations(case)),
        ("refusal_check", lambda: check_refusal(case)),
        ("safety_phrases", lambda: check_safety_phrases(case)),
        ("latency_cost", lambda: check_latency_cost(case)),
    ]

    for name, fn in check_fns:
        checks_run.append(name)
        result = fn()
        if len(result) == 2:
            ok, partial_metrics = result
            signals: list[FailureSignal] = []
        else:
            ok, partial_metrics, signals = result

        skipped = (
            partial_metrics.get("skipped")
            or partial_metrics.get("exact_match") is None
            and name == "exact_match"
            and not case.expected_answer
            or partial_metrics.get("format_check") == "skipped"
            or partial_metrics.get("citation_check") == "skipped"
            or partial_metrics.get("refusal_check") == "skipped"
            or partial_metrics.get("unsupported_claim_check") == "skipped"
        )
        if not skipped:
            total_checks += 1
            if ok:
                pass_count += 1
        metrics.update(partial_metrics)
        all_signals.extend(signals)

    failure_labels = list(dict.fromkeys(s.label for s in all_signals))
    if not failure_labels:
        failure_labels = [FailureLabel.CORRECT]

    critical_fail = any(
        s.label
        in {
            FailureLabel.SAFETY_REVIEW_REQUIRED,
            FailureLabel.HALLUCINATION_RISK,
            FailureLabel.UNSUPPORTED_CLAIM,
        }
        and s.severity == "high"
        for s in all_signals
    )
    any_fail = bool(all_signals)

    if not any_fail:
        status: EvalStatus = "pass"
    elif critical_fail or pass_count == 0:
        status = "fail"
    else:
        status = "partial"

    limitations = list(BASELINE_LIMITATIONS)
    if any_fail:
        limitations.append(
            "Classification is not accusation — failure labels indicate eval triage only."
        )

    policy = evaluate_eval_policy(case, failure_labels=failure_labels, failure_signals=all_signals)

    return EvalResult(
        case_id=case.case_id,
        task_type=case.task_type,
        status=status,
        failure_labels=failure_labels,
        failure_signals=all_signals,
        metrics=metrics,
        limitations=limitations,
        confidence_level=_confidence_from_checks(pass_count, total_checks),
        policy_decision=policy,
        checks_run=checks_run,
        recommendation=policy.recommendation,
    )


def load_eval_cases(path: Path, *, repo_root: Path | None = None) -> list[EvalCase]:
    """Load eval cases.

    Args:
        path: path supplied by the caller.
        repo_root: repo root supplied by the caller.

    Returns:
        The computed `list[EvalCase]` value.

    Side effects:
        Reads data from the requested source.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    raw_cases = data.get("cases", data if isinstance(data, list) else [])
    cases: list[EvalCase] = []
    for item in raw_cases:
        if "model_output" in item and isinstance(item["model_output"], dict):
            item = {**item, "model_output": ModelOutput.model_validate(item["model_output"])}
        cases.append(EvalCase.model_validate(item))
    return cases


def run_eval_suite(cases: list[EvalCase]) -> EvalReport:
    """Run eval suite.

    Args:
        cases: cases supplied by the caller.

    Returns:
        The computed `EvalReport` value.

    Side effects:
        Executes the configured evaluation or processing flow.
    """
    results = [evaluate_case(case) for case in cases]
    taxonomy: dict[str, int] = {}
    policy_dist: dict[str, int] = {}
    high_risk: list[str] = []

    for result in results:
        for label in result.failure_labels:
            taxonomy[label.value] = taxonomy.get(label.value, 0) + 1
        gate = result.policy_decision.gate.value
        policy_dist[gate] = policy_dist.get(gate, 0) + 1
        if (
            result.policy_decision.requires_human_review
            or result.policy_decision.gate == EvalPolicyGate.BLOCK
        ):
            high_risk.append(result.case_id)

    pass_count = sum(1 for r in results if r.status == "pass")
    fail_count = sum(1 for r in results if r.status == "fail")
    partial_count = sum(1 for r in results if r.status == "partial")

    return EvalReport(
        total_cases=len(results),
        pass_count=pass_count,
        fail_count=fail_count,
        partial_count=partial_count,
        results=results,
        taxonomy_distribution=taxonomy,
        policy_distribution=policy_dist,
        high_risk_cases=high_risk,
        limitations=list(BASELINE_LIMITATIONS)
        + ["This report is not a formal model safety certification."],
    )
