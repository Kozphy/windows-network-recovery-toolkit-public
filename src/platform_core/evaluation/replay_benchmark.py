"""Evidence replay benchmark — proves deterministic pipeline behavior offline."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.platform_core.governance.chain_of_custody import verify_chain
from windows_network_toolkit.analytics_pipeline import (
    load_audit_rows,
    run_endpoint_analytics_pipeline,
)

_CANONICAL_KEYS = ("incidents", "control_tests", "risk_scores")


class ReplayBenchmarkResult(BaseModel):
    """Per-case replay determinism outcome."""

    case_id: str
    fixture_path: str = ""
    deterministic: bool
    audit_verified: bool | None = None
    audit_message: str = ""
    run_hashes: list[str] = Field(default_factory=list)
    duration_ms: int = 0


class ReplayBenchmarkSummary(BaseModel):
    """Aggregate replay benchmark metrics."""

    schema_version: str = "replay_benchmark.v1"
    replay_count: int = 2
    deterministic_match_rate: float = 0.0
    nondeterministic_case_count: int = 0
    audit_verification_pass_rate: float = 0.0
    replay_duration_ms: int = 0
    results: list[ReplayBenchmarkResult] = Field(default_factory=list)
    positioning: str = (
        "Deterministic replay benchmark for endpoint evidence analytics pipeline."
    )


def _repo_root(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    return Path(__file__).resolve().parents[3]


def _canonical_hash(payload: dict[str, Any]) -> str:
    subset = {k: payload.get(k) for k in _CANONICAL_KEYS}
    blob = json.dumps(subset, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_case_fixture(case: dict[str, Any], *, repo_root: Path) -> dict[str, Any]:
    if case.get("fixture"):
        return case["fixture"]
    path_str = case.get("fixture_path") or case.get("input_fixture_path") or ""
    if not path_str:
        raise ValueError(f"replay case {case.get('case_id')} missing fixture")
    path = Path(path_str)
    if not path.is_absolute():
        path = repo_root / path
    return json.loads(path.read_text(encoding="utf-8"))


def load_replay_cases(path: Path, *, repo_root: Path | None = None) -> list[dict[str, Any]]:
    """Load replay cases from JSONL."""
    root = _repo_root(repo_root)
    file_path = path if path.is_absolute() else root / path
    cases: list[dict[str, Any]] = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            cases.append(json.loads(line))
    return cases


def run_replay_benchmark(
    cases: list[dict[str, Any]],
    *,
    replay_count: int = 2,
    repo_root: Path | None = None,
) -> ReplayBenchmarkSummary:
    """Run replay benchmark over fixture cases."""
    root = _repo_root(repo_root)
    results: list[ReplayBenchmarkResult] = []
    total_ms = 0
    audit_checks = 0
    audit_pass = 0

    for case in cases:
        case_id = str(case.get("case_id", "unknown"))
        fixture = _load_case_fixture(case, repo_root=root)
        fixture_path = str(case.get("fixture_path") or case.get("input_fixture_path") or "")

        start = time.perf_counter()
        hashes: list[str] = []
        for _ in range(max(2, replay_count)):
            payload = run_endpoint_analytics_pipeline(fixture=fixture)
            hashes.append(_canonical_hash(payload))
        duration_ms = int((time.perf_counter() - start) * 1000)
        total_ms += duration_ms

        deterministic = len(set(hashes)) == 1

        audit_verified: bool | None = None
        audit_message = ""
        audit_path_str = case.get("audit_path")
        if audit_path_str:
            audit_checks += 1
            audit_path = Path(audit_path_str)
            if not audit_path.is_absolute():
                audit_path = root / audit_path
            rows = load_audit_rows(input_path=audit_path)
            ok, msg = verify_chain(rows)
            audit_verified = ok
            audit_message = msg
            if ok:
                audit_pass += 1

        results.append(
            ReplayBenchmarkResult(
                case_id=case_id,
                fixture_path=fixture_path,
                deterministic=deterministic,
                audit_verified=audit_verified,
                audit_message=audit_message,
                run_hashes=hashes,
                duration_ms=duration_ms,
            )
        )

    total = len(results) or 1
    return ReplayBenchmarkSummary(
        replay_count=replay_count,
        deterministic_match_rate=sum(1 for r in results if r.deterministic) / total,
        nondeterministic_case_count=sum(1 for r in results if not r.deterministic),
        audit_verification_pass_rate=(audit_pass / audit_checks) if audit_checks else 1.0,
        replay_duration_ms=total_ms,
        results=results,
    )


def render_replay_benchmark_markdown(summary: ReplayBenchmarkSummary) -> str:
    """Render markdown replay benchmark report."""
    lines = [
        "# Evidence Replay Benchmark",
        "",
        f"_{summary.positioning}_",
        "",
        "## Why deterministic replay matters",
        "",
        "- Platform engineering: regression tests catch classifier drift.",
        "- Auditability: reviewers can reproduce the same decision from stored evidence.",
        "- Incident review: stable outputs prevent false escalation between runs.",
        "- False escalation prevention: nondeterministic labels erode trust in triage.",
        "",
        "## Summary metrics",
        "",
        f"- **replay_count:** {summary.replay_count}",
        f"- **deterministic_match_rate:** {summary.deterministic_match_rate:.2%}",
        f"- **nondeterministic_case_count:** {summary.nondeterministic_case_count}",
        f"- **audit_verification_pass_rate:** {summary.audit_verification_pass_rate:.2%}",
        f"- **replay_duration_ms:** {summary.replay_duration_ms}",
        "",
        "## Per-case results",
        "",
        "| case_id | deterministic | audit_verified | duration_ms |",
        "|---------|---------------|----------------|-------------|",
    ]
    for row in summary.results:
        audit_cell = (
            "n/a"
            if row.audit_verified is None
            else ("pass" if row.audit_verified else f"fail ({row.audit_message})")
        )
        lines.append(
            f"| {row.case_id} | {'yes' if row.deterministic else 'no'} | {audit_cell} | {row.duration_ms} |"
        )
    return "\n".join(lines) + "\n"
