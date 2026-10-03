"""Offline evaluation harness for ``email_risk`` (metrics, confusion, ablations).

Module responsibility:
    Run the deterministic email-risk engine over a labeled synthetic dataset
    (``tests/fixtures/email_risk/eval/dataset.json``) and report detection
    metrics (precision, recall, F1, FPR, FNR), per-tag recall, critical false
    negatives, confusion matrices, attack-family attribution accuracy, and
    component ablations.

Key invariants:
    * Fixture-only. No network, no mailbox access; URLs are never visited.
    * Metrics are reported, not gated — poor results are shown, not hidden.
    * A prediction is positive when ``risk_level >= MEDIUM``; the stricter
      ``>= HIGH`` operating point is reported alongside.
    * ``CRITICAL_FALSE_NEGATIVE`` = a case labelled ``critical`` (malicious
      executive / payment attack) predicted LOW or UNKNOWN.
    * Output is deterministic for a given ruleset and dataset (no timestamps,
      no random IDs in the report).

Side effects:
    Reads fixture files only.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from src.platform_core.email_risk.correlation import level_rank
from src.platform_core.email_risk.engine import analyze_email_file
from src.platform_core.email_risk.models import (
    CLASSIFIER_VERSION,
    POLICY_VERSION,
    RULESET_VERSION,
    AttackFamily,
    EmailRiskConfig,
    EmailRiskLevel,
    SignalCategory,
)
from src.platform_core.email_risk.parser import EmailParseError
from src.platform_core.email_risk.qr_decode import decoder_available
from src.platform_core.email_risk.scoring import SIGNAL_CATEGORY

REPORT_SCHEMA_VERSION = "email_risk_benchmark.v1"
FIXTURE_ROOT_PARTS = ("tests", "fixtures", "email_risk")
DEFAULT_DATASET_PARTS = (*FIXTURE_ROOT_PARTS, "eval", "dataset.json")
REPORTED_TAGS: tuple[str, ...] = (
    "bec",
    "qr_phishing",
    "payment_fraud",
    "executive_impersonation",
    "credential_phishing",
    "channel_migration",
)
LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")

BENCHMARK_LIMITATIONS: tuple[str, ...] = (
    "Offline evaluation on a small synthetic dataset written by the same authors as the "
    "rules; results measure coverage of known patterns, not real-world performance.",
    "No real-world prevalence: precision and FPR here do not predict production alert "
    "volume, where benign mail vastly outnumbers attacks.",
    "Adversarial results cover only the listed perturbations; no general adversarial "
    "robustness is claimed.",
    "QR cases requiring the optional decoder are skipped (and counted as skipped) when "
    "Pillow + zxing-cpp are unavailable.",
    "Confidence values are uncalibrated support indices and are not evaluated as probabilities.",
)


class DatasetError(ValueError):
    """Raised when the dataset manifest is missing or malformed."""


class DatasetCase(BaseModel):
    """One labeled evaluation case."""

    id: str
    file: str
    config: dict[str, Any] = Field(default_factory=dict)
    category_no: int = Field(ge=1)
    category: str
    label: Literal["malicious", "benign"]
    critical: bool = False
    expected_family: AttackFamily = AttackFamily.NONE
    acceptable_families: list[AttackFamily] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    split: Literal["core", "adversarial"] = "core"
    requires: list[str] = Field(default_factory=list)
    min_level: EmailRiskLevel | None = None
    notes: str = ""


class CaseOutcome(BaseModel):
    """Engine output for one case, reduced to what evaluation needs."""

    id: str
    category: str
    split: str
    label: str
    critical: bool
    tags: list[str] = Field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    predicted_level: str = "UNKNOWN"
    score: float = 0.0
    attack_chain: str = "NONE"
    expected_family: str = "NONE"
    family_correct: bool | None = None
    family_exact: bool | None = None
    positive: bool = False
    positive_high: bool = False
    outcome: Literal["TP", "FP", "TN", "FN", "SKIPPED"] = "SKIPPED"
    critical_false_negative: bool = False
    min_level_met: bool | None = None
    signals: list[str] = Field(default_factory=list)
    correlation_rules: list[str] = Field(default_factory=list)
    policy_decisions: list[str] = Field(default_factory=list)


class BinaryMetrics(BaseModel):
    """Confusion counts and derived rates (``None`` when undefined)."""

    n: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    fpr: float | None = None
    fnr: float | None = None
    accuracy: float | None = None


class TagRecall(BaseModel):
    """Detection recall among malicious cases carrying ``tag``."""

    tag: str
    n: int
    detected: int
    recall: float | None


class SplitReport(BaseModel):
    """Metrics for one dataset split (core / adversarial / all)."""

    name: str
    cases: int
    skipped: int
    metrics: BinaryMetrics
    metrics_high_threshold: BinaryMetrics
    tag_recall: list[TagRecall] = Field(default_factory=list)
    critical_cases: int = 0
    critical_false_negatives: list[str] = Field(default_factory=list)
    critical_below_high: list[str] = Field(default_factory=list)
    min_level_misses: list[str] = Field(default_factory=list)
    level_by_label: dict[str, dict[str, int]] = Field(default_factory=dict)
    family_accuracy: float | None = None
    family_accuracy_strict: float | None = None
    family_evaluated: int = 0
    family_confusion: dict[str, dict[str, int]] = Field(default_factory=dict)
    false_positives: list[dict[str, Any]] = Field(default_factory=list)
    false_negatives: list[dict[str, Any]] = Field(default_factory=list)
    family_errors: list[dict[str, Any]] = Field(default_factory=list)


class AblationResult(BaseModel):
    """One ablation run compared against the full system (``all`` split)."""

    name: str
    description: str
    disabled_signals: list[str] = Field(default_factory=list)
    correlation_enabled: bool = True
    qr_decode: bool = True
    metrics: BinaryMetrics
    metrics_high_threshold: BinaryMetrics
    critical_false_negatives: int
    delta_precision: float | None = None
    delta_recall: float | None = None
    delta_f1: float | None = None
    delta_fpr: float | None = None
    delta_recall_high: float | None = None
    delta_critical_false_negatives: int = 0
    malicious_level_downgrades: int = 0
    critical_level_lost: int = 0
    mean_malicious_score_delta: float | None = None
    newly_missed: list[str] = Field(default_factory=list)
    newly_flagged: list[str] = Field(default_factory=list)


class EmailRiskBenchmarkReport(BaseModel):
    """Full, deterministic benchmark report."""

    schema_version: str = REPORT_SCHEMA_VERSION
    ruleset_version: str = RULESET_VERSION
    classifier_version: str = CLASSIFIER_VERSION
    policy_version: str = POLICY_VERSION
    dataset: str
    dataset_schema: str
    qr_decoder_available: bool
    positive_threshold: str = "MEDIUM"
    outcomes: list[CaseOutcome]
    splits: dict[str, SplitReport]
    ablations: list[AblationResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=lambda: list(BENCHMARK_LIMITATIONS))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_dataset_path() -> Path:
    """Return the built-in dataset manifest path."""
    return _repo_root().joinpath(*DEFAULT_DATASET_PARTS)


def load_dataset(path: Path | None = None) -> tuple[str, list[DatasetCase]]:
    """Load and validate the dataset manifest; returns ``(schema, cases)``."""
    target = path or default_dataset_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetError(f"cannot read dataset {target}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("cases"), list):
        raise DatasetError("dataset must be an object with a 'cases' list")
    try:
        cases = [DatasetCase.model_validate(item) for item in raw["cases"]]
    except ValidationError as exc:
        raise DatasetError(f"invalid dataset case: {exc}") from exc
    ids = [c.id for c in cases]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise DatasetError(f"duplicate case ids: {duplicates}")
    return str(raw.get("schema", "")), cases


def _is_positive(level: EmailRiskLevel, threshold: EmailRiskLevel) -> bool:
    return level != EmailRiskLevel.UNKNOWN and level_rank(level) >= level_rank(threshold)


def _skip(case: DatasetCase, reason: str) -> CaseOutcome:
    return CaseOutcome(
        id=case.id,
        category=case.category,
        split=case.split,
        label=case.label,
        critical=case.critical,
        tags=list(case.tags),
        skipped=True,
        skip_reason=reason,
        expected_family=case.expected_family.value,
    )


def evaluate_case(
    case: DatasetCase,
    *,
    fixture_root: Path,
    overlay: dict[str, Any] | None = None,
    qr_available: bool,
) -> CaseOutcome:
    """Analyze one case and compare it against its label."""
    if "qr_decoder" in case.requires and not qr_available:
        return _skip(case, "optional QR decoder not installed")
    config = EmailRiskConfig().merged(case.config).merged(overlay or {})
    try:
        result = analyze_email_file(fixture_root / case.file, config=config)
    except EmailParseError as exc:
        return _skip(case, f"parse error: {exc}")
    level = result.risk_level
    positive = _is_positive(level, EmailRiskLevel.MEDIUM)
    malicious = case.label == "malicious"
    outcome: Literal["TP", "FP", "TN", "FN"]
    if malicious:
        outcome = "TP" if positive else "FN"
    else:
        outcome = "FP" if positive else "TN"
    family_correct: bool | None = None
    family_exact: bool | None = None
    if malicious and positive:
        family_correct = result.attack_chain in {case.expected_family, *case.acceptable_families}
        family_exact = result.attack_chain == case.expected_family
    return CaseOutcome(
        id=case.id,
        category=case.category,
        split=case.split,
        label=case.label,
        critical=case.critical,
        tags=list(case.tags),
        predicted_level=level.value,
        score=result.score,
        attack_chain=result.attack_chain.value,
        expected_family=case.expected_family.value,
        family_correct=family_correct,
        family_exact=family_exact,
        positive=positive,
        positive_high=_is_positive(level, EmailRiskLevel.HIGH),
        outcome=outcome,
        critical_false_negative=case.critical
        and level_rank(level) <= level_rank(EmailRiskLevel.LOW),
        min_level_met=(None if case.min_level is None else _is_positive(level, case.min_level)),
        signals=list(result.signals),
        correlation_rules=list(result.correlation_rules),
        policy_decisions=[d.value for d in result.policy.decisions],
    )


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def binary_metrics(outcomes: Sequence[CaseOutcome], *, high: bool = False) -> BinaryMetrics:
    """Compute confusion counts and rates over non-skipped outcomes."""
    tp = fp = tn = fn = 0
    for o in outcomes:
        if o.skipped:
            continue
        predicted = o.positive_high if high else o.positive
        if o.label == "malicious":
            tp, fn = (tp + 1, fn) if predicted else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if predicted else (fp, tn + 1)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 3)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    return BinaryMetrics(
        n=tp + fp + tn + fn,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=_ratio(fp, fp + tn),
        fnr=_ratio(fn, fn + tp),
        accuracy=_ratio(tp + tn, tp + fp + tn + fn),
    )


def _tag_recall(outcomes: Sequence[CaseOutcome]) -> list[TagRecall]:
    out: list[TagRecall] = []
    for tag in REPORTED_TAGS:
        relevant = [
            o for o in outcomes if not o.skipped and o.label == "malicious" and tag in o.tags
        ]
        detected = sum(1 for o in relevant if o.positive)
        out.append(
            TagRecall(
                tag=tag, n=len(relevant), detected=detected, recall=_ratio(detected, len(relevant))
            )
        )
    return out


def _example(o: CaseOutcome) -> dict[str, Any]:
    return {
        "id": o.id,
        "category": o.category,
        "predicted_level": o.predicted_level,
        "score": o.score,
        "attack_chain": o.attack_chain,
        "signals": o.signals,
    }


def split_report(name: str, outcomes: Sequence[CaseOutcome]) -> SplitReport:
    """Aggregate metrics, confusion matrices, and error examples for one split."""
    evaluated = [o for o in outcomes if not o.skipped]
    level_by_label: dict[str, dict[str, int]] = {
        label: dict.fromkeys(LEVELS, 0) for label in ("malicious", "benign")
    }
    for o in evaluated:
        level_by_label[o.label][o.predicted_level] += 1
    family_rows = [o for o in evaluated if o.family_correct is not None]
    confusion: dict[str, dict[str, int]] = {}
    for o in family_rows:
        row = confusion.setdefault(o.expected_family, {})
        row[o.attack_chain] = row.get(o.attack_chain, 0) + 1
    correct = sum(1 for o in family_rows if o.family_correct)
    exact = sum(1 for o in family_rows if o.family_exact)
    return SplitReport(
        name=name,
        cases=len(outcomes),
        skipped=len(outcomes) - len(evaluated),
        metrics=binary_metrics(evaluated),
        metrics_high_threshold=binary_metrics(evaluated, high=True),
        tag_recall=_tag_recall(evaluated),
        critical_cases=sum(1 for o in evaluated if o.critical),
        critical_false_negatives=[o.id for o in evaluated if o.critical_false_negative],
        critical_below_high=[o.id for o in evaluated if o.critical and not o.positive_high],
        min_level_misses=[o.id for o in evaluated if o.min_level_met is False],
        level_by_label=level_by_label,
        family_accuracy=_ratio(correct, len(family_rows)),
        family_accuracy_strict=_ratio(exact, len(family_rows)),
        family_evaluated=len(family_rows),
        family_confusion={k: dict(sorted(v.items())) for k, v in sorted(confusion.items())},
        false_positives=[_example(o) for o in evaluated if o.outcome == "FP"],
        false_negatives=[_example(o) for o in evaluated if o.outcome == "FN"],
        family_errors=[
            {**_example(o), "expected_family": o.expected_family}
            for o in family_rows
            if not o.family_correct
        ],
    )


def _signals_in(*categories: SignalCategory) -> list[str]:
    return sorted(s for s, c in SIGNAL_CATEGORY.items() if c in categories)


ABLATIONS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    (
        "no_authentication",
        "Drop SPF/DKIM/DMARC, Reply-To and Return-Path signals and missing-auth context.",
        {
            "disabled_signals": [
                *_signals_in(SignalCategory.HEADER_AUTHENTICATION),
                "authentication_missing",
            ]
        },
    ),
    (
        "no_social_engineering",
        "Drop urgency, secrecy, and authority-pressure signals.",
        {"disabled_signals": _signals_in(SignalCategory.SOCIAL_ENGINEERING)},
    ),
    (
        "no_website_risk",
        "Drop URL signals produced from website_risk (suspicious_url, suspicious_qr_url).",
        {"disabled_signals": _signals_in(SignalCategory.URL)},
    ),
    (
        "no_qr",
        "Disable QR decoding and drop all QR request / QR URL signals.",
        {
            "qr_decode": False,
            "disabled_signals": [
                *_signals_in(SignalCategory.QR, SignalCategory.ARTIFACT),
                "suspicious_qr_url",
            ],
        },
    ),
    (
        "no_payment_intent",
        "Drop all payment-category signals (payment, wire, bank change, invoice, gift card, crypto).",
        {"disabled_signals": _signals_in(SignalCategory.PAYMENT)},
    ),
    (
        "no_identity",
        "Drop impersonation and look-alike signals (additional ablation).",
        {"disabled_signals": _signals_in(SignalCategory.IDENTITY)},
    ),
    (
        "no_correlation",
        "Disable all correlation rules and level floors (pure additive scoring).",
        {"correlation_enabled": False},
    ),
)


def _delta(new: float | None, base: float | None) -> float | None:
    return None if new is None or base is None else round(new - base, 3)


def run_ablations(
    cases: Sequence[DatasetCase],
    baseline: Sequence[CaseOutcome],
    *,
    fixture_root: Path,
    qr_available: bool,
) -> list[AblationResult]:
    """Re-run the dataset with each component removed and compare to ``baseline``."""
    base_metrics = binary_metrics(baseline)
    base_high = binary_metrics(baseline, high=True)
    base_critical = sum(1 for o in baseline if o.critical_false_negative)
    base_by_id = {o.id: o for o in baseline}
    results: list[AblationResult] = []
    for name, description, overlay in ABLATIONS:
        outcomes = [
            evaluate_case(c, fixture_root=fixture_root, overlay=overlay, qr_available=qr_available)
            for c in cases
        ]
        metrics = binary_metrics(outcomes)
        high = binary_metrics(outcomes, high=True)
        critical = sum(1 for o in outcomes if o.critical_false_negative)
        live = [o for o in outcomes if not o.skipped]
        malicious = [o for o in live if o.label == "malicious"]
        score_deltas = [o.score - base_by_id[o.id].score for o in malicious]
        results.append(
            AblationResult(
                name=name,
                description=description,
                disabled_signals=list(overlay.get("disabled_signals", [])),
                correlation_enabled=bool(overlay.get("correlation_enabled", True)),
                qr_decode=bool(overlay.get("qr_decode", True)),
                metrics=metrics,
                metrics_high_threshold=high,
                critical_false_negatives=critical,
                delta_precision=_delta(metrics.precision, base_metrics.precision),
                delta_recall=_delta(metrics.recall, base_metrics.recall),
                delta_f1=_delta(metrics.f1, base_metrics.f1),
                delta_fpr=_delta(metrics.fpr, base_metrics.fpr),
                delta_recall_high=_delta(high.recall, base_high.recall),
                delta_critical_false_negatives=critical - base_critical,
                malicious_level_downgrades=sum(
                    1
                    for o in malicious
                    if level_rank(EmailRiskLevel(o.predicted_level))
                    < level_rank(EmailRiskLevel(base_by_id[o.id].predicted_level))
                ),
                critical_level_lost=sum(
                    1
                    for o in malicious
                    if base_by_id[o.id].predicted_level == "CRITICAL"
                    and o.predicted_level != "CRITICAL"
                ),
                mean_malicious_score_delta=(
                    round(sum(score_deltas) / len(score_deltas), 3) if score_deltas else None
                ),
                newly_missed=[
                    o.id
                    for o in live
                    if o.label == "malicious" and not o.positive and base_by_id[o.id].positive
                ],
                newly_flagged=[
                    o.id
                    for o in live
                    if o.label == "benign" and o.positive and not base_by_id[o.id].positive
                ],
            )
        )
    return results


def run_email_risk_benchmark(
    *,
    dataset_path: Path | None = None,
    include_ablations: bool = True,
    qr_available: bool | None = None,
) -> EmailRiskBenchmarkReport:
    """Run the full benchmark and return a deterministic report."""
    schema, cases = load_dataset(dataset_path)
    fixture_root = _repo_root().joinpath(*FIXTURE_ROOT_PARTS)
    available = decoder_available() if qr_available is None else qr_available
    outcomes = [evaluate_case(c, fixture_root=fixture_root, qr_available=available) for c in cases]
    splits = {
        "core": split_report("core", [o for o in outcomes if o.split == "core"]),
        "adversarial": split_report(
            "adversarial", [o for o in outcomes if o.split == "adversarial"]
        ),
        "all": split_report("all", outcomes),
    }
    ablations = (
        run_ablations(cases, outcomes, fixture_root=fixture_root, qr_available=available)
        if include_ablations
        else []
    )
    target = dataset_path or default_dataset_path()
    try:
        dataset_label = target.resolve().relative_to(_repo_root()).as_posix()
    except ValueError:
        dataset_label = target.as_posix()
    return EmailRiskBenchmarkReport(
        dataset=dataset_label,
        dataset_schema=schema,
        qr_decoder_available=available,
        outcomes=outcomes,
        splits=splits,
        ablations=ablations,
    )


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _fmt_delta(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+.3f}"


def _metrics_row(label: str, m: BinaryMetrics) -> str:
    return (
        f"| {label} | {m.n} | {m.tp} | {m.fp} | {m.tn} | {m.fn} | {_fmt(m.precision)} | "
        f"{_fmt(m.recall)} | {_fmt(m.f1)} | {_fmt(m.fpr)} | {_fmt(m.fnr)} |"
    )


def render_email_risk_benchmark_markdown(report: EmailRiskBenchmarkReport) -> str:
    """Render the report as Markdown (metrics, confusion, errors, ablations)."""
    lines = [
        "# Email risk benchmark",
        "",
        f"- Ruleset: `{report.ruleset_version}`; classifier: `{report.classifier_version}`; "
        f"policy: `{report.policy_version}`",
        f"- Dataset: `{report.dataset}` ({report.dataset_schema})",
        f"- Positive = risk_level >= {report.positive_threshold}; "
        f"QR decoder available: {report.qr_decoder_available}",
        "",
        "## Detection metrics",
        "",
        "| Split | N | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for split in report.splits.values():
        lines.append(_metrics_row(f"{split.name} (>=MEDIUM)", split.metrics))
        lines.append(_metrics_row(f"{split.name} (>=HIGH)", split.metrics_high_threshold))
    lines += [
        "",
        "Skipped cases: " + ", ".join(f"{s.name}={s.skipped}" for s in report.splits.values()),
        "",
    ]

    all_split = report.splits["all"]
    lines += ["## Critical false negatives", ""]
    for split in report.splits.values():
        missed = ", ".join(split.critical_false_negatives) or "none"
        lines.append(
            f"- {split.name}: {len(split.critical_false_negatives)} / {split.critical_cases} "
            f"critical cases predicted LOW/UNKNOWN ({missed})"
        )
    lines += ["", "Secondary (not counted as CRITICAL_FALSE_NEGATIVE):", ""]
    for split in report.splits.values():
        lines.append(
            f"- {split.name}: critical cases below HIGH: "
            f"{', '.join(split.critical_below_high) or 'none'}; "
            f"per-case min_level not met: {', '.join(split.min_level_misses) or 'none'}"
        )
    lines += [
        "",
        "## Per-tag recall (>=MEDIUM)",
        "",
        "| Tag | Split | N | Detected | Recall |",
        "|---|---|---|---|---|",
    ]
    for split in report.splits.values():
        lines.extend(
            f"| {t.tag} | {split.name} | {t.n} | {t.detected} | {_fmt(t.recall)} |"
            for t in split.tag_recall
            if t.n
        )

    lines += [
        "",
        "## Confusion matrix (all, >=MEDIUM)",
        "",
        "| | Predicted positive | Predicted negative |",
        "|---|---|---|",
        f"| Malicious | {all_split.metrics.tp} | {all_split.metrics.fn} |",
        f"| Benign | {all_split.metrics.fp} | {all_split.metrics.tn} |",
        "",
        "### Risk level by label (all)",
        "",
        "| Label | " + " | ".join(LEVELS) + " |",
        "|---" * (len(LEVELS) + 1) + "|",
    ]
    for label, row in all_split.level_by_label.items():
        lines.append(f"| {label} | " + " | ".join(str(row[lv]) for lv in LEVELS) + " |")

    lines += ["", "## Attack-family attribution (detected malicious cases)", ""]
    for split in report.splits.values():
        lines.append(
            f"- {split.name}: accuracy {_fmt(split.family_accuracy)} (expected or acceptable "
            f"family), strict {_fmt(split.family_accuracy_strict)} (expected family only), over "
            f"{split.family_evaluated} detected malicious cases"
        )
    lines += ["", "| Expected \\ Predicted | Counts |", "|---|---|"]
    for expected, row in all_split.family_confusion.items():
        cells = ", ".join(f"{k}: {v}" for k, v in row.items())
        lines.append(f"| {expected} | {cells} |")

    lines += ["", "## Error examples (all)", ""]
    for title, items in (
        ("False positives", all_split.false_positives),
        ("False negatives", all_split.false_negatives),
        ("Family attribution errors", all_split.family_errors),
    ):
        lines.append(f"### {title}")
        lines.append("")
        if not items:
            lines.append("- none")
        for item in items:
            expected = f" (expected {item['expected_family']})" if "expected_family" in item else ""
            lines.append(
                f"- `{item['id']}` [{item['category']}] level={item['predicted_level']} "
                f"score={item['score']:.2f} chain={item['attack_chain']}{expected}; "
                f"signals: {', '.join(item['signals']) or 'none'}"
            )
        lines.append("")

    if report.ablations:
        base = all_split.metrics
        base_high = all_split.metrics_high_threshold
        lines += [
            "## Ablations (all split)",
            "",
            "Detection at >=MEDIUM, plus recall at >=HIGH and level movement on malicious "
            "cases (scores saturate at 1.0, so the MEDIUM threshold alone understates impact).",
            "",
            "| Variant | P | R | F1 | FPR | Crit FN | ΔP | ΔR | ΔF1 | ΔFPR | ΔCritFN | "
            "R@HIGH | ΔR@HIGH | Downgrades | CRITICAL lost | Mean Δscore | Newly missed |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
            f"| full | {_fmt(base.precision)} | {_fmt(base.recall)} | {_fmt(base.f1)} | "
            f"{_fmt(base.fpr)} | {len(all_split.critical_false_negatives)} | - | - | - | - | - | "
            f"{_fmt(base_high.recall)} | - | - | - | - | - |",
        ]
        for ab in report.ablations:
            m = ab.metrics
            lines.append(
                f"| {ab.name} | {_fmt(m.precision)} | {_fmt(m.recall)} | {_fmt(m.f1)} | "
                f"{_fmt(m.fpr)} | {ab.critical_false_negatives} | {_fmt_delta(ab.delta_precision)} | "
                f"{_fmt_delta(ab.delta_recall)} | {_fmt_delta(ab.delta_f1)} | "
                f"{_fmt_delta(ab.delta_fpr)} | {ab.delta_critical_false_negatives:+d} | "
                f"{_fmt(ab.metrics_high_threshold.recall)} | {_fmt_delta(ab.delta_recall_high)} | "
                f"{ab.malicious_level_downgrades} | {ab.critical_level_lost} | "
                f"{_fmt_delta(ab.mean_malicious_score_delta)} | "
                f"{', '.join(ab.newly_missed) or '-'} |"
            )
        lines.append("")

    lines += [
        "## Per-case outcomes",
        "",
        "| Case | Split | Label | Critical | Level | Score | Chain | Outcome | Policy |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for o in report.outcomes:
        if o.skipped:
            lines.append(
                f"| {o.id} | {o.split} | {o.label} | {o.critical} | skipped | – | – | "
                f"SKIPPED ({o.skip_reason}) | – |"
            )
            continue
        flag = " ⚠ CRITICAL_FN" if o.critical_false_negative else ""
        lines.append(
            f"| {o.id} | {o.split} | {o.label} | {o.critical} | {o.predicted_level} | "
            f"{o.score:.2f} | {o.attack_chain} | {o.outcome}{flag} | "
            f"{', '.join(o.policy_decisions)} |"
        )
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in report.limitations)
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "ABLATIONS",
    "DatasetCase",
    "DatasetError",
    "EmailRiskBenchmarkReport",
    "binary_metrics",
    "default_dataset_path",
    "evaluate_case",
    "load_dataset",
    "render_email_risk_benchmark_markdown",
    "run_email_risk_benchmark",
    "split_report",
]
