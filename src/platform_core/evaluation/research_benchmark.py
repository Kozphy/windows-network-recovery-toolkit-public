"""Reproducible B0-B3 benchmark for endpoint proxy-risk classification.

The harness is fixture-only.  It never reads or mutates live Windows state.  Raw
case outcomes are written separately from derived metrics so every aggregate can
be regenerated and audited.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import platform
import subprocess
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from windows_network_toolkit.analytics_pipeline import normalize_events_from_fixture
from windows_network_toolkit.incident_classifier import classify_incident_from_events

BASELINES = ("B0_CONNECTIVITY", "B1_FLAT_RULES", "B2_HEALTH_STATUS", "B3_FULL_PLATFORM")
ABLATIONS = ("A1_NO_LISTENER", "A2_NO_PATH_HEALTH", "A3_NO_WINHTTP_CONTRAST", "A4_NO_TIMELINE")
ABSTAIN_LABEL = "INSUFFICIENT_DATA"
_TIER_RANK = {f"T{index}": index for index in range(8)}
_UNSAFE_POLICY_MODES = {"APPLY_DIRECTLY", "AUTO_REMEDIATE"}


class _StrictEvidenceModel(BaseModel):
    """Base contract for nested, repository-authored benchmark evidence."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ProxyStateEvidence(_StrictEvidenceModel):
    """Observed WinINET/WinHTTP proxy state for one endpoint."""

    timestamp_utc: str
    endpoint_id: str
    wininet_proxy_enabled: bool
    wininet_proxy_server: str
    winhttp_direct_access: bool
    localhost_port: int | None = None


class ProcessEvidence(_StrictEvidenceModel):
    """Process attributed to a local proxy listener."""

    pid: int
    name: str
    exe_path: str | None = None
    cmdline: str | list[str] | None = None


class ProxyOwnerEvidence(_StrictEvidenceModel):
    """Listener observation and optional process attribution."""

    timestamp_utc: str
    endpoint_id: str
    listener_found: bool
    localhost_port: int
    process: ProcessEvidence | None = None
    writer_proof: bool | None = None
    sysmon_event_id: int | None = None

    @model_validator(mode="after")
    def _listener_requires_process(self) -> ProxyOwnerEvidence:
        if self.listener_found and self.process is None:
            raise ValueError("process evidence is required when listener_found is true")
        return self


class HealthEvidence(_StrictEvidenceModel):
    """Direct-versus-proxy path-health observation."""

    timestamp_utc: str
    endpoint_id: str
    proxy_status: str
    direct_probe_ok: bool
    proxy_probe_ok: bool | None
    tcp_listening: bool | None = None
    tcp_connect_ok: bool | None = None
    proxy_https_connect_ok: bool | None = None
    failure_reason: str | None = None
    external_probe_ok: bool | None = None


class HealthAuditEvidence(_StrictEvidenceModel):
    """Audit wrapper accepted by the existing fixture normalizer."""

    timestamp_utc: str
    endpoint_id: str | None = None
    health: HealthEvidence


class ProxyTransitionState(_StrictEvidenceModel):
    """Relevant proxy fields before or after a timeline transition."""

    wininet_proxy_enabled: bool
    wininet_proxy_server: str
    localhost_port: int | None = None


class ReverterDiagnosis(_StrictEvidenceModel):
    """Precomputed temporal diagnosis attached to a transition."""

    status: str


class TimelineEvidence(_StrictEvidenceModel):
    """One chronological proxy-state transition."""

    timestamp_utc: str
    endpoint_id: str
    old_state: ProxyTransitionState
    new_state: ProxyTransitionState
    reverter_suspected: bool
    reverter_diagnosis: ReverterDiagnosis


class SignalBundle(_StrictEvidenceModel):
    """Validated evidence families allowed in proxy-risk benchmark v1."""

    proxy_state: ProxyStateEvidence | None = None
    proxy_owner: ProxyOwnerEvidence | None = None
    health_inject: HealthEvidence | None = None
    health_audit: HealthAuditEvidence | None = None
    timeline: list[TimelineEvidence] = Field(default_factory=list)


class ResearchCase(BaseModel):
    """One versioned, offline research case with a predeclared expected outcome."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["proxy_risk_case.v1"] = "proxy_risk_case.v1"
    case_id: str
    split: Literal["development", "held_out", "adversarial"]
    scenario_name: str
    expected_class: str
    expected_min_tier: str = "T1"
    expected_policy: Literal["OBSERVE", "PREVIEW_ONLY", "HUMAN_REVIEW", "BLOCK"] = (
        "PREVIEW_ONLY"
    )
    signals: dict[str, Any] = Field(default_factory=dict)
    provenance: str
    limitations: list[str] = Field(min_length=1)
    ambiguity_allowed: bool = False

    @field_validator("signals", mode="before")
    @classmethod
    def _valid_signals(cls, value: Any) -> dict[str, Any]:
        """Reject malformed nested evidence before any baseline sees the case."""
        validated = SignalBundle.model_validate(value)
        return validated.model_dump(mode="python", exclude_unset=True)

    @field_validator("case_id", "scenario_name", "expected_class", "provenance")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be blank")
        return value.strip()

    @field_validator("expected_min_tier")
    @classmethod
    def _valid_tier(cls, value: str) -> str:
        token = value.strip().upper().split("_", 1)[0]
        if token not in _TIER_RANK:
            raise ValueError("expected_min_tier must start with T0 through T7")
        return token


class BenchmarkConfig(BaseModel):
    """Frozen inputs for one benchmark run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["proxy_risk_benchmark_config.v1"] = (
        "proxy_risk_benchmark_config.v1"
    )
    benchmark_version: str = "v1"
    seed: int = 42
    cases_root: str = "tests/fixtures/research/proxy_risk_v1"
    splits: list[str] = Field(default_factory=lambda: ["development", "held_out", "adversarial"])
    baselines: list[str] = Field(default_factory=lambda: list(BASELINES))
    ablations: list[str] = Field(default_factory=lambda: list(ABLATIONS))

    @field_validator("baselines")
    @classmethod
    def _known_baselines(cls, values: list[str]) -> list[str]:
        unknown = sorted(set(values) - set(BASELINES))
        if unknown:
            raise ValueError(f"unknown baselines: {', '.join(unknown)}")
        if not values:
            raise ValueError("at least one baseline is required")
        if len(values) != len(set(values)):
            raise ValueError("baselines must not contain duplicates")
        return values

    @field_validator("ablations")
    @classmethod
    def _known_ablations(cls, values: list[str]) -> list[str]:
        unknown = sorted(set(values) - set(ABLATIONS))
        if unknown:
            raise ValueError(f"unknown ablations: {', '.join(unknown)}")
        if len(values) != len(set(values)):
            raise ValueError("ablations must not contain duplicates")
        return values

    @field_validator("splits")
    @classmethod
    def _known_splits(cls, values: list[str]) -> list[str]:
        allowed = {"development", "held_out", "adversarial"}
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise ValueError(f"unknown splits: {', '.join(unknown)}")
        if not values:
            raise ValueError("at least one split is required")
        if len(values) != len(set(values)):
            raise ValueError("splits must not contain duplicates")
        return values


class Prediction(BaseModel):
    """Normalized output shared by all benchmark baselines."""

    predicted_class: str
    predicted_policy: str
    proof_tier: str = "T0"
    limitations: list[str] = Field(default_factory=list)


class CaseResult(BaseModel):
    """Machine-readable outcome for one case/baseline pair."""

    benchmark_version: str
    case_id: str
    split: str
    baseline: str
    expected_class: str
    predicted_class: str
    expected_policy: str
    predicted_policy: str
    expected_min_tier: str
    proof_tier: str
    classification_supported: bool
    classification_match: bool
    policy_match: bool
    abstained: bool
    unsafe_action_proposed: bool
    ambiguity_allowed: bool
    limitations: list[str]
    runtime_ms: float
    digest: str
    replay_mismatch: bool


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _repo_root(explicit: Path | None = None) -> Path:
    return explicit.resolve() if explicit else Path(__file__).resolve().parents[3]


def load_config(path: Path, *, repo_root: Path | None = None) -> BenchmarkConfig:
    """Load and validate a frozen benchmark configuration."""
    root = _repo_root(repo_root)
    config_path = path if path.is_absolute() else root / path
    return BenchmarkConfig.model_validate_json(config_path.read_text(encoding="utf-8"))


def load_research_cases(
    cases_root: Path,
    *,
    include_splits: Iterable[str] | None = None,
) -> list[ResearchCase]:
    """Load case JSON files, rejecting duplicate IDs and split-directory drift."""
    allowed = set(include_splits or ("development", "held_out", "adversarial"))
    cases: list[ResearchCase] = []
    seen: set[str] = set()
    for path in sorted(cases_root.rglob("*.json")):
        case = ResearchCase.model_validate_json(path.read_text(encoding="utf-8"))
        if case.split not in allowed:
            continue
        if path.parent.name != case.split:
            raise ValueError(
                f"case {case.case_id} declares split {case.split!r} but is stored under "
                f"{path.parent.name!r}"
            )
        if case.case_id in seen:
            raise ValueError(f"duplicate case_id: {case.case_id}")
        seen.add(case.case_id)
        cases.append(case)
    if not cases:
        raise ValueError(f"no research cases found under {cases_root}")
    return cases


def dataset_digest(cases: Iterable[ResearchCase]) -> str:
    """Return a stable digest over validated case content, independent of file paths."""
    payload = [case.model_dump(mode="json") for case in sorted(cases, key=lambda row: row.case_id)]
    return _digest(payload)


def _health(signals: dict[str, Any]) -> dict[str, Any]:
    if isinstance(signals.get("health_inject"), dict):
        return dict(signals["health_inject"])
    health_audit = signals.get("health_audit")
    if isinstance(health_audit, dict):
        nested = health_audit.get("health")
        return dict(nested) if isinstance(nested, dict) else dict(health_audit)
    return {}


def _policy_from_action(action: str) -> str:
    token = action.strip().lower()
    if token in {"human_review", "investigate_network_path", "alert_reverter_suspected"}:
        return "HUMAN_REVIEW"
    if token in {
        "block_or_disable_preview",
        "alert_high_risk_proxy_transition",
        "preview",
        "preview_only",
    }:
        return "PREVIEW_ONLY"
    if token in {"block"}:
        return "BLOCK"
    return "OBSERVE"


def _max_event_tier(signals: dict[str, Any]) -> str:
    events = normalize_events_from_fixture(signals)
    if not events:
        return "T0"
    return max((event.evidence_tier.split("_", 1)[0] for event in events), key=_tier_value)


def _tier_value(value: str) -> int:
    return _TIER_RANK.get(value.upper().split("_", 1)[0], -1)


def _b0_connectivity(signals: dict[str, Any]) -> Prediction:
    health = _health(signals)
    direct_ok = health.get("direct_probe_ok")
    if direct_ok is True:
        predicted = "NO_PROXY_DIRECT_OK"
        policy = "OBSERVE"
    elif direct_ok is False:
        predicted = "BOTH_DIRECT_AND_PROXY_FAIL"
        policy = "HUMAN_REVIEW"
    else:
        predicted = ABSTAIN_LABEL
        policy = "OBSERVE"
    return Prediction(
        predicted_class=predicted,
        predicted_policy=policy,
        proof_tier="T0",
        limitations=["Connectivity-only baseline cannot attribute proxy-path failure."],
    )


def _b1_flat_rules(signals: dict[str, Any]) -> Prediction:
    state = signals.get("proxy_state") if isinstance(signals.get("proxy_state"), dict) else {}
    owner = signals.get("proxy_owner") if isinstance(signals.get("proxy_owner"), dict) else {}
    enabled = state.get("wininet_proxy_enabled")
    listener = owner.get("listener_found")
    if enabled is False:
        predicted, policy = "NO_PROXY_DIRECT_OK", "OBSERVE"
    elif enabled is True and listener is False:
        predicted, policy = "DEAD_PROXY_CONFIG", "APPLY_DIRECTLY"
    elif enabled is True and listener is True:
        predicted, policy = "LOCAL_PROXY_ACTIVE", "OBSERVE"
    elif enabled is True:
        predicted, policy = "UNKNOWN_LOCAL_PROXY", "HUMAN_REVIEW"
    else:
        predicted, policy = ABSTAIN_LABEL, "OBSERVE"
    return Prediction(
        predicted_class=predicted,
        predicted_policy=policy,
        proof_tier="T0",
        limitations=["Flat-rule baseline does not aggregate path evidence or proof tiers."],
    )


def _b2_health_status(signals: dict[str, Any]) -> Prediction:
    status = str(_health(signals).get("proxy_status") or "").upper()
    mapping = {
        "DIRECT_ONLY_WORKS": ("DIRECT_ONLY_WORKS", "PREVIEW_ONLY"),
        "LISTENER_NOT_PROXY": ("LISTENER_NOT_PROXY", "HUMAN_REVIEW"),
        "PROXY_FORWARDING_FAILED": ("PROXY_FORWARDING_FAILED", "HUMAN_REVIEW"),
        "BOTH_DIRECT_AND_PROXY_WORK": ("BOTH_DIRECT_AND_PROXY_WORK", "OBSERVE"),
        "HEALTHY_LOCALHOST_PROXY": ("BOTH_DIRECT_AND_PROXY_WORK", "OBSERVE"),
        "PROXY_ONLY_WORKS": ("PROXY_ONLY_WORKS", "OBSERVE"),
        "BOTH_DIRECT_AND_PROXY_FAIL": ("BOTH_DIRECT_AND_PROXY_FAIL", "HUMAN_REVIEW"),
    }
    predicted, policy = mapping.get(status, (ABSTAIN_LABEL, "OBSERVE"))
    return Prediction(
        predicted_class=predicted,
        predicted_policy=policy,
        proof_tier="T0",
        limitations=["Health-status baseline ignores configuration and listener evidence."],
    )


def _b3_full_platform(signals: dict[str, Any]) -> Prediction:
    events = normalize_events_from_fixture(signals)
    incident = classify_incident_from_events(events)
    return Prediction(
        predicted_class=incident.incident_class,
        predicted_policy=_policy_from_action(incident.recommended_policy_action),
        proof_tier=_max_event_tier(signals),
        limitations=list(incident.limitations),
    )


def _without(signals: dict[str, Any], *keys: str) -> dict[str, Any]:
    reduced = copy.deepcopy(signals)
    for key in keys:
        reduced.pop(key, None)
    return reduced


def _a1_no_listener(signals: dict[str, Any]) -> Prediction:
    return _b3_full_platform(_without(signals, "proxy_owner"))


def _a2_no_path_health(signals: dict[str, Any]) -> Prediction:
    return _b3_full_platform(_without(signals, "health_inject", "health_audit"))


def _a3_no_winhttp_contrast(signals: dict[str, Any]) -> Prediction:
    reduced = copy.deepcopy(signals)
    state = reduced.get("proxy_state")
    if isinstance(state, dict):
        state["winhttp_direct_access"] = None
    return _b3_full_platform(reduced)


def _a4_no_timeline(signals: dict[str, Any]) -> Prediction:
    return _b3_full_platform(_without(signals, "timeline"))


_RUNNERS: dict[str, Callable[[dict[str, Any]], Prediction]] = {
    "B0_CONNECTIVITY": _b0_connectivity,
    "B1_FLAT_RULES": _b1_flat_rules,
    "B2_HEALTH_STATUS": _b2_health_status,
    "B3_FULL_PLATFORM": _b3_full_platform,
    "A1_NO_LISTENER": _a1_no_listener,
    "A2_NO_PATH_HEALTH": _a2_no_path_health,
    "A3_NO_WINHTTP_CONTRAST": _a3_no_winhttp_contrast,
    "A4_NO_TIMELINE": _a4_no_timeline,
}


def _prediction_digest(prediction: Prediction) -> str:
    return _digest(prediction.model_dump(mode="json"))


def _run_case(case: ResearchCase, baseline: str, benchmark_version: str) -> CaseResult:
    runner = _RUNNERS[baseline]
    start = time.perf_counter_ns()
    first = runner(case.signals)
    runtime_ms = (time.perf_counter_ns() - start) / 1_000_000
    second = runner(case.signals)
    first_digest = _prediction_digest(first)
    replay_mismatch = first_digest != _prediction_digest(second)
    abstained = first.predicted_class == ABSTAIN_LABEL
    supported = bool(
        abstained
        or (
            first.limitations
            and _tier_value(first.proof_tier) >= _tier_value(case.expected_min_tier)
        )
    )
    return CaseResult(
        benchmark_version=benchmark_version,
        case_id=case.case_id,
        split=case.split,
        baseline=baseline,
        expected_class=case.expected_class,
        predicted_class=first.predicted_class,
        expected_policy=case.expected_policy,
        predicted_policy=first.predicted_policy,
        expected_min_tier=case.expected_min_tier,
        proof_tier=first.proof_tier,
        classification_supported=supported,
        classification_match=first.predicted_class == case.expected_class,
        policy_match=first.predicted_policy == case.expected_policy,
        abstained=abstained,
        unsafe_action_proposed=first.predicted_policy in _UNSAFE_POLICY_MODES,
        ambiguity_allowed=case.ambiguity_allowed,
        limitations=first.limitations,
        runtime_ms=round(runtime_ms, 6),
        digest=first_digest,
        replay_mismatch=replay_mismatch,
    )


def _git_commit(root: Path, revision: str = "HEAD") -> str:
    """Resolve a Git revision to its canonical 40-character commit SHA."""
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    resolved = completed.stdout.strip()
    if completed.returncode != 0 or len(resolved) != 40:
        raise ValueError(f"invalid Git commit revision: {revision!r}")
    return resolved


def execute_benchmark(
    config_path: Path,
    output_dir: Path,
    *,
    repo_root: Path | None = None,
    code_revision: str | None = None,
) -> dict[str, Any]:
    """Execute all configured baselines and write raw results plus a frozen manifest."""
    root = _repo_root(repo_root)
    resolved_revision = _git_commit(root, code_revision or "HEAD")
    config_file = config_path if config_path.is_absolute() else root / config_path
    config = load_config(config_file, repo_root=root)
    cases_dir = Path(config.cases_root)
    if not cases_dir.is_absolute():
        cases_dir = root / cases_dir
    cases = load_research_cases(cases_dir, include_splits=config.splits)
    out = output_dir if output_dir.is_absolute() else root / output_dir
    out.mkdir(parents=True, exist_ok=True)

    experiment_variants = [*config.baselines, *config.ablations]
    results = [
        _run_case(case, baseline, config.benchmark_version)
        for case in cases
        for baseline in experiment_variants
    ]
    raw_path = out / "case_results.json"
    raw_path.write_text(
        json.dumps(
            [row.model_dump(mode="json") for row in results],
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": "proxy_risk_benchmark_manifest.v1",
        "benchmark_version": config.benchmark_version,
        "git_commit": resolved_revision,
        "dataset": {
            "name": "proxy-risk-benchmark",
            "version": config.benchmark_version,
            "sha256": dataset_digest(cases),
            "case_count": len(cases),
            "split_counts": dict(sorted(Counter(case.split for case in cases).items())),
        },
        "config_sha256": _digest(config.model_dump(mode="json")),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "seed": config.seed,
        "baselines": config.baselines,
        "ablations": config.ablations,
        "raw_results_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def load_case_results(results_dir: Path) -> list[CaseResult]:
    """Load machine-generated case-level JSON results."""
    path = results_dir / "case_results.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"case results must be a JSON array: {path}")
    rows = [CaseResult.model_validate(row) for row in payload]
    if not rows:
        raise ValueError(f"no case results found in {path}")
    return rows


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _per_class_rows(
    rows: list[CaseResult],
    *,
    benchmark_version: str,
    split: str,
    baseline: str,
) -> list[dict[str, Any]]:
    labels = sorted({row.expected_class for row in rows} | {row.predicted_class for row in rows})
    output: list[dict[str, Any]] = []
    for label in labels:
        tp = sum(row.expected_class == label and row.predicted_class == label for row in rows)
        fp = sum(row.expected_class != label and row.predicted_class == label for row in rows)
        fn = sum(row.expected_class == label and row.predicted_class != label for row in rows)
        tn = len(rows) - tp - fp - fn
        precision = _safe_ratio(tp, tp + fp)
        recall = _safe_ratio(tp, tp + fn)
        output.append(
            {
                "benchmark_version": benchmark_version,
                "split": split,
                "baseline": baseline,
                "class": label,
                "support": tp + fn,
                "precision": precision,
                "recall": recall,
                "f1": _safe_ratio(2 * precision * recall, precision + recall),
                "false_positive_rate": _safe_ratio(fp, fp + tn),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            }
        )
    return output


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_report(results_dir: Path, output_dir: Path) -> dict[str, Path]:
    """Derive all CSV/Markdown benchmark artifacts from raw case-level outcomes."""
    rows = load_case_results(results_dir)
    manifest = json.loads((results_dir / "manifest.json").read_text(encoding="utf-8"))
    expected_raw_digest = str(manifest.get("raw_results_sha256") or "")
    actual_raw_digest = hashlib.sha256((results_dir / "case_results.json").read_bytes()).hexdigest()
    if expected_raw_digest != actual_raw_digest:
        raise ValueError("raw results digest does not match manifest")

    output_dir.mkdir(parents=True, exist_ok=True)
    benchmark_version = str(manifest["benchmark_version"])
    grouped: dict[tuple[str, str], list[CaseResult]] = defaultdict(list)
    for row in rows:
        grouped[(row.split, row.baseline)].append(row)
        grouped[("all", row.baseline)].append(row)

    summary_rows: list[dict[str, Any]] = []
    per_class: list[dict[str, Any]] = []
    confusion: list[dict[str, Any]] = []
    for (split, baseline), group in sorted(grouped.items()):
        class_rows = _per_class_rows(
            group,
            benchmark_version=benchmark_version,
            split=split,
            baseline=baseline,
        )
        per_class.extend(class_rows)
        summary_rows.append(
            {
                "benchmark_version": benchmark_version,
                "split": split,
                "model_or_baseline": baseline,
                "case_count": len(group),
                "accuracy": _safe_ratio(sum(row.classification_match for row in group), len(group)),
                "macro_precision": _safe_ratio(sum(row["precision"] for row in class_rows), len(class_rows)),
                "macro_recall": _safe_ratio(sum(row["recall"] for row in class_rows), len(class_rows)),
                "macro_f1": _safe_ratio(sum(row["f1"] for row in class_rows), len(class_rows)),
                "macro_false_positive_rate": _safe_ratio(
                    sum(row["false_positive_rate"] for row in class_rows), len(class_rows)
                ),
                "unsupported_classification_rate": _safe_ratio(
                    sum(not row.classification_supported for row in group), len(group)
                ),
                "abstention_rate": _safe_ratio(sum(row.abstained for row in group), len(group)),
                "policy_match_rate": _safe_ratio(sum(row.policy_match for row in group), len(group)),
                "unsafe_action_proposal_rate": _safe_ratio(
                    sum(row.unsafe_action_proposed for row in group), len(group)
                ),
                "replay_mismatch_count": sum(row.replay_mismatch for row in group),
                "mean_runtime_ms": _safe_ratio(sum(row.runtime_ms for row in group), len(group)),
                "git_commit": manifest["git_commit"],
                "dataset_digest": manifest["dataset"]["sha256"],
            }
        )
        counts = Counter((row.expected_class, row.predicted_class) for row in group)
        confusion.extend(
            {
                "benchmark_version": benchmark_version,
                "split": split,
                "model_or_baseline": baseline,
                "expected_class": expected,
                "predicted_class": predicted,
                "count": count,
            }
            for (expected, predicted), count in sorted(counts.items())
        )

    result_columns = [
        "benchmark_version",
        "split",
        "model_or_baseline",
        "case_count",
        "accuracy",
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "macro_false_positive_rate",
        "unsupported_classification_rate",
        "abstention_rate",
        "policy_match_rate",
        "unsafe_action_proposal_rate",
        "replay_mismatch_count",
        "mean_runtime_ms",
        "git_commit",
        "dataset_digest",
    ]
    _write_csv(output_dir / "results.csv", summary_rows, result_columns)
    _write_csv(
        output_dir / "per_class_metrics.csv",
        per_class,
        [
            "benchmark_version",
            "split",
            "baseline",
            "class",
            "support",
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "tp",
            "fp",
            "fn",
            "tn",
        ],
    )
    _write_csv(
        output_dir / "confusion_matrix.csv",
        confusion,
        [
            "benchmark_version",
            "split",
            "model_or_baseline",
            "expected_class",
            "predicted_class",
            "count",
        ],
    )

    all_summaries = {
        str(row["model_or_baseline"]): row
        for row in summary_rows
        if row["split"] == "all"
    }
    full_summary = all_summaries.get("B3_FULL_PLATFORM")
    ablation_rows: list[dict[str, Any]] = []
    if full_summary:
        for name in ABLATIONS:
            row = all_summaries.get(name)
            if not row:
                continue
            ablation_rows.append(
                {
                    "benchmark_version": benchmark_version,
                    "split": "all",
                    "ablation": name,
                    "case_count": row["case_count"],
                    "macro_f1": row["macro_f1"],
                    "unsupported_classification_rate": row[
                        "unsupported_classification_rate"
                    ],
                    "unsafe_action_proposal_rate": row["unsafe_action_proposal_rate"],
                    "replay_mismatch_count": row["replay_mismatch_count"],
                    "delta_macro_f1_vs_full": row["macro_f1"] - full_summary["macro_f1"],
                    "delta_unsupported_rate_vs_full": row[
                        "unsupported_classification_rate"
                    ]
                    - full_summary["unsupported_classification_rate"],
                    "notes": "Input evidence family removed; all remaining pipeline behavior is unchanged.",
                }
            )
    _write_csv(
        output_dir / "ablations.csv",
        ablation_rows,
        [
            "benchmark_version",
            "split",
            "ablation",
            "case_count",
            "macro_f1",
            "unsupported_classification_rate",
            "unsafe_action_proposal_rate",
            "replay_mismatch_count",
            "delta_macro_f1_vs_full",
            "delta_unsupported_rate_vs_full",
            "notes",
        ],
    )

    failures = [row for row in rows if not row.classification_match or not row.policy_match]
    failure_lines = [
        "# Benchmark v1 Failure Analysis",
        "",
        "Generated from case-level results. Failures are retained; this file is not a claim of production performance.",
        "",
        "| case | split | baseline | expected | predicted | expected policy | predicted policy |",
        "|---|---|---|---|---|---|---|",
    ]
    failure_lines.extend(
        f"| {row.case_id} | {row.split} | {row.baseline} | {row.expected_class} | "
        f"{row.predicted_class} | {row.expected_policy} | {row.predicted_policy} |"
        for row in failures
    )
    failure_lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Synthetic, fixture-only benchmark; it does not estimate production prevalence.",
            "- Cases were authored in this repository and are not independent external validation.",
            "- Runtime values are descriptive for this run and are not an MTTR measurement.",
            "- Confidence and proof tiers are ordinal, not calibrated probabilities.",
        ]
    )
    (output_dir / "failure_analysis.md").write_text(
        "\n".join(failure_lines) + "\n", encoding="utf-8"
    )
    environment = {
        key: manifest[key]
        for key in ("schema_version", "benchmark_version", "git_commit", "python_version", "platform", "seed")
    }
    environment["dataset"] = manifest["dataset"]
    (output_dir / "environment.json").write_text(
        json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    all_rows = [
        row
        for row in summary_rows
        if row["split"] == "all" and str(row["model_or_baseline"]).startswith("B")
    ]
    report_lines = [
        "# Proxy Risk Benchmark v1",
        "",
        "Fixture-only comparison of connectivity, flat-rule, health-only, and full evidence-tiered diagnosis.",
        "",
        "| Baseline | Cases | Accuracy | Macro F1 | Unsupported | Unsafe action proposals |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in sorted(all_rows, key=lambda item: item["model_or_baseline"]):
        report_lines.append(
            f"| {row['model_or_baseline']} | {row['case_count']} | {row['accuracy']:.3f} | "
            f"{row['macro_f1']:.3f} | {row['unsupported_classification_rate']:.3f} | "
            f"{row['unsafe_action_proposal_rate']:.3f} |"
        )
    report_lines.extend(
        [
            "",
            "## Reproduce",
            "",
            "```powershell",
            "python experiments/scripts/run_benchmark.py --config experiments/configs/proxy-risk-v1.json --out experiments/results/v1",
            "python experiments/scripts/build_report.py --results experiments/results/v1 --out benchmarks/v1",
            "```",
            "",
            "## Claim boundary",
            "",
            "These results describe this versioned fixture set only. They do not establish enterprise accuracy, MTTR reduction, malware detection, or autonomous-remediation safety.",
        ]
    )
    (output_dir / "benchmark_report.md").write_text(
        "\n".join(report_lines) + "\n", encoding="utf-8"
    )
    return {
        name: output_dir / name
        for name in (
            "results.csv",
            "per_class_metrics.csv",
            "confusion_matrix.csv",
            "ablations.csv",
            "failure_analysis.md",
            "environment.json",
            "benchmark_report.md",
        )
    }


def run_cli(argv: list[str] | None = None) -> int:
    """Small shared CLI used by thin experiment scripts."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--out", required=True, type=Path)
    run.add_argument(
        "--code-revision",
        default=None,
        help="Published code commit SHA; defaults to the current checkout HEAD.",
    )
    report = sub.add_parser("report")
    report.add_argument("--results", required=True, type=Path)
    report.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    root = _repo_root()
    if args.command == "run":
        manifest = execute_benchmark(
            args.config,
            args.out,
            repo_root=root,
            code_revision=args.code_revision,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        artifacts = build_report(
            args.results if args.results.is_absolute() else root / args.results,
            args.out if args.out.is_absolute() else root / args.out,
        )
        print("\n".join(str(path) for path in artifacts.values()))
    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
