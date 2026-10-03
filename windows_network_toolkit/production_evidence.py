"""Production-evidence gate for WNRT.

This module intentionally separates synthetic benchmark evidence from live-deployment
observations. Synthetic runs can prove regression discipline; only explicitly supplied
live observations can satisfy the production-evidence gate.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from windows_network_toolkit.fleet_benchmark import run_fleet_benchmark

DEFAULT_POLICY = Path("production/slo_policy.json")


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool
    observed: float | int | str | None
    target: float | int | str | None
    detail: str


def _compare(observed: float, operator: str, target: float) -> bool:
    if operator == ">=":
        return observed >= target
    if operator == "<=":
        return observed <= target
    raise ValueError(f"unsupported operator: {operator}")


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    """Load the versioned SLO policy."""
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_live_observation(
    observation: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate real deployment observations against minimum evidence and SLO gates."""
    results: list[GateResult] = []
    minimum = policy["minimum_evidence"]

    source = observation.get("evidence_source")
    results.append(
        GateResult(
            "LIVE_DEPLOYMENT_SOURCE",
            source == "live_deployment",
            source,
            "live_deployment",
            "Synthetic or replay evidence cannot satisfy production readiness.",
        )
    )

    for field in ("deployment_id", "commit_sha", "observed_at"):
        value = observation.get(field)
        results.append(
            GateResult(
                f"PROVENANCE_{field.upper()}",
                isinstance(value, str) and bool(value.strip()),
                value,
                "non-empty",
                "Production evidence must be attributable to a deployment and commit.",
            )
        )

    for field, target in minimum.items():
        observed = observation.get(field)
        passed = isinstance(observed, (int, float)) and observed >= target
        results.append(
            GateResult(
                f"MINIMUM_{field.upper()}",
                passed,
                observed,
                target,
                "Minimum sample size/window prevents one-off smoke tests being called production proof.",
            )
        )

    metrics = observation.get("metrics") or {}
    for metric, spec in policy["slos"].items():
        observed = metrics.get(metric)
        operator = spec["operator"]
        target = float(spec["target"])
        passed = isinstance(observed, (int, float)) and _compare(float(observed), operator, target)
        results.append(
            GateResult(
                f"SLO_{metric.upper()}",
                passed,
                observed,
                f"{operator} {target}",
                "Observed deployment SLI evaluated against the versioned SLO target.",
            )
        )

    passed = all(result.passed for result in results)
    return {
        "schema_version": "wnrt-production-evidence.v1",
        "gate": "PRODUCTION_EVIDENCE_READY",
        "status": "PASS" if passed else "FAIL",
        "claim_level": "production_evidence_candidate"
        if passed
        else "insufficient_production_evidence",
        "results": [result.__dict__ for result in results],
        "observation": observation,
        "policy_schema_version": policy.get("schema_version"),
        "non_claims": [
            "A passing evidence bundle is not an external SLA, certification, or audit opinion.",
            "The gate does not prove internet-scale or multi-region capacity.",
            "Synthetic benchmark results are never substituted for live deployment observations.",
        ],
    }


def build_synthetic_evidence(
    *, endpoints: int, measurement_cap: int, seed: int, scenario: str
) -> dict[str, Any]:
    """Generate explicitly synthetic scale/regression evidence."""
    benchmark = run_fleet_benchmark(
        endpoints=endpoints,
        measurement_cap=measurement_cap,
        seed=seed,
        scenario=scenario,
    )
    correctness_pass = (
        benchmark.get("execution_failures", 0) == 0
        and benchmark.get("unknown_classification_ratio", 1.0) <= 0.02
    )
    return {
        "schema_version": "wnrt-production-evidence.v1",
        "gate": "SYNTHETIC_SCALE_EVIDENCE",
        "status": "PASS" if correctness_pass else "FAIL",
        "claim_level": "synthetic_benchmark_only",
        "benchmark": benchmark,
        "non_claims": [
            "This run is not production deployment evidence.",
            "Simulated endpoint count is not live fleet capacity.",
            "Local latency and throughput are not an SLA.",
        ],
    }


def render_markdown(bundle: dict[str, Any]) -> str:
    """Render a compact reviewer-facing evidence report."""
    lines = [
        "# WNRT Production Evidence Report",
        "",
        f"- **Schema:** `{bundle.get('schema_version')}`",
        f"- **Gate:** `{bundle.get('gate')}`",
        f"- **Status:** **{bundle.get('status')}**",
        f"- **Claim level:** `{bundle.get('claim_level')}`",
        "",
    ]
    if "results" in bundle:
        lines.extend(
            ["## Gate results", "", "| Gate | Pass | Observed | Target |", "|---|---:|---|---|"]
        )
        for item in bundle["results"]:
            lines.append(
                f"| `{item['name']}` | {item['passed']} | {item['observed']} | {item['target']} |"
            )
    if "benchmark" in bundle:
        benchmark = bundle["benchmark"]
        lines.extend(
            [
                "## Synthetic benchmark boundary",
                "",
                f"- Simulated endpoints: {benchmark.get('simulated_endpoints')}",
                f"- Measured endpoints: {benchmark.get('measured_endpoints')}",
                f"- p95 local pipeline latency: {benchmark.get('latency_p95_ms')} ms",
                f"- Execution failure ratio: {benchmark.get('execution_failure_ratio')}",
                "",
            ]
        )
    lines.extend(["## Non-claims", ""])
    lines.extend(f"- {item}" for item in bundle.get("non_claims", []))
    return "\n".join(lines) + "\n"


def _write_bundle(bundle: dict[str, Any], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out.with_suffix(".md").write_text(render_markdown(bundle), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="WNRT production evidence gate")
    parser.add_argument("--mode", choices=("synthetic", "live"), required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--observation", type=Path)
    parser.add_argument(
        "--out", type=Path, default=Path("reports/production-evidence/evidence.json")
    )
    parser.add_argument("--endpoints", type=int, default=1000)
    parser.add_argument("--measurement-cap", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--scenario", default="mixed_proxy_failures")
    args = parser.parse_args()

    if args.mode == "live":
        if args.observation is None:
            parser.error("--observation is required in live mode")
        observation = json.loads(args.observation.read_text(encoding="utf-8"))
        bundle = evaluate_live_observation(observation, load_policy(args.policy))
    else:
        bundle = build_synthetic_evidence(
            endpoints=args.endpoints,
            measurement_cap=args.measurement_cap,
            seed=args.seed,
            scenario=args.scenario,
        )

    _write_bundle(bundle, args.out)
    return 0 if bundle["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
