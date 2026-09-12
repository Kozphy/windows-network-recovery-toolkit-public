"""AI evals feedback loop — fixture-based LLM evaluation harness.

Deterministic evaluation of pre-recorded model outputs against JSON fixture cases.
Each case embeds a ``model_output`` field; no live LLM or retrieval API calls are made.

Modules:
    evaluator: Case loading, heuristic checks, and suite aggregation.
    failure_taxonomy: Failure labels, policy gates, and phrase heuristics.
    policy: Maps failure labels to eval policy decisions.
    report: Markdown and JSON report renderers.
    schemas: Pydantic models for cases, results, and reports.

Note:
    Eval results are structured triage signals — not formal model safety certification.
"""

from __future__ import annotations

from .evaluator import evaluate_case, load_eval_cases, run_eval_suite
from .failure_taxonomy import EvalPolicyGate, FailureLabel
from .policy import evaluate_eval_policy, normalize_eval_policy
from .report import render_eval_json, render_eval_markdown
from .schemas import EvalCase, EvalPolicyDecision, EvalReport, EvalResult, ModelOutput

__all__ = [
    "EvalCase",
    "EvalPolicyDecision",
    "EvalPolicyGate",
    "EvalReport",
    "EvalResult",
    "FailureLabel",
    "ModelOutput",
    "evaluate_case",
    "evaluate_eval_policy",
    "load_eval_cases",
    "normalize_eval_policy",
    "render_eval_json",
    "render_eval_markdown",
    "run_eval_suite",
]
