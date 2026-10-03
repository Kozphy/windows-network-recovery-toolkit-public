"""FinOps cost export — mock-first cost analytics layer."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope

SCHEMA_VERSION = "finops_export.v1"

DEFAULT_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "finops" / "mock_costs.json"
)

FACT_COSTS_COLUMNS = [
    "cost_id",
    "provider",
    "resource_id",
    "resource_name",
    "service",
    "category",
    "monthly_cost_usd",
    "budget_category",
    "date_key",
    "anomaly_flag",
]


def default_fixture_path() -> Path:
    """Return default fixture path.

    Returns:
        The computed `Path` value.

    Side effects:
        None.
    """
    return DEFAULT_FIXTURE_PATH


def load_finops_fixture(path: Path | str | None = None) -> dict[str, Any]:
    """Load finops fixture.

    Args:
        path: path supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Raises:
        Exception: Propagates validation or I/O failures from the operation.

    Side effects:
        Reads data from the requested source.
    """
    fixture_path = Path(path) if path else DEFAULT_FIXTURE_PATH
    if not fixture_path.is_file():
        raise FileNotFoundError(f"FinOps fixture not found: {fixture_path}")
    return json.loads(fixture_path.read_text(encoding="utf-8"))


def build_finops_export(
    *,
    fixture_path: Path | str | None = None,
    fixture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build FinOps export payload from mock cost snapshot."""
    data = fixture if fixture is not None else load_finops_fixture(fixture_path)
    costs = list(data.get("costs") or [])
    total = sum(float(c.get("monthly_cost_usd") or 0.0) for c in costs)
    by_provider: dict[str, float] = {}
    for row in costs:
        provider = str(row.get("provider") or "unknown")
        by_provider[provider] = by_provider.get(provider, 0.0) + float(
            row.get("monthly_cost_usd") or 0.0
        )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source_schema": data.get("schema_version", "finops_cost_snapshot.v1"),
        "period": data.get("period", ""),
        "fact_costs": costs,
        "summary": {
            "total_monthly_cost_usd": round(total, 2),
            "cost_line_count": len(costs),
            "by_provider_usd": {k: round(v, 2) for k, v in by_provider.items()},
            "anomaly_count": sum(1 for c in costs if c.get("anomaly_flag")),
        },
        "limitations": list(data.get("limitations") or [])
        + ["FinOps export is read-only — no billing API mutations."],
    }
    return attach_governance_envelope(payload, limitations=payload["limitations"])


def write_fact_costs_csv(rows: list[dict[str, Any]], out_path: Path) -> None:
    """Write fact costs csv.

    Args:
        rows: rows supplied by the caller.
        out_path: out path supplied by the caller.

    Returns:
        None.

    Side effects:
        Writes output to the requested destination.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FACT_COSTS_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def export_finops(
    *,
    fixture_path: Path | str | None = None,
    out_dir: Path | None = None,
    fmt: str = "json",
) -> dict[str, Any]:
    """Export FinOps data as JSON and/or CSV."""
    payload = build_finops_export(fixture_path=fixture_path)
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "fact_costs.json"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        payload["json_path"] = str(json_path.resolve())
        if fmt in ("csv", "both"):
            csv_path = out_dir / "fact_costs.csv"
            write_fact_costs_csv(payload["fact_costs"], csv_path)
            payload["csv_path"] = str(csv_path.resolve())
    payload["export_format"] = fmt
    return payload
