"""Cloud governance recommendations — mock-first advisory layer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope

SCHEMA_VERSION = "cloud_governance_summary.v1"

DEFAULT_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "cloud_governance"
    / "mock_recommendations.json"
)

_PILLAR_LABELS = {
    "cost_optimization": "Cost Optimization",
    "security": "Security",
    "reliability": "High Availability",
    "operational_excellence": "Operational Excellence",
}


def default_fixture_path() -> Path:
    """Return default fixture path.

    Returns:
        The computed `Path` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return DEFAULT_FIXTURE_PATH


def load_cloud_recommendations(path: Path | str | None = None) -> dict[str, Any]:
    """Load cloud recommendations.

    Args:
        path: path supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Raises:
        Exception: Propagates validation or I/O failures from the operation.

    Side effects:
        Reads data from the requested source.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    fixture_path = Path(path) if path else DEFAULT_FIXTURE_PATH
    if not fixture_path.is_file():
        raise FileNotFoundError(f"Cloud governance fixture not found: {fixture_path}")
    return json.loads(fixture_path.read_text(encoding="utf-8"))


def summarize_cloud_recommendations(
    *,
    fixture_path: Path | str | None = None,
    fixture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize mock cloud governance recommendations by pillar and provider."""
    data = fixture if fixture is not None else load_cloud_recommendations(fixture_path)
    recommendations = list(data.get("recommendations") or [])
    by_pillar: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    savings = 0.0
    for row in recommendations:
        pillar = str(row.get("pillar") or "unknown")
        provider = str(row.get("provider") or "unknown")
        by_pillar[pillar] = by_pillar.get(pillar, 0) + 1
        by_provider[provider] = by_provider.get(provider, 0) + 1
        savings += float(row.get("estimated_monthly_savings_usd") or 0.0)

    top_savings = sorted(
        recommendations,
        key=lambda r: float(r.get("estimated_monthly_savings_usd") or 0.0),
        reverse=True,
    )[:5]

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source_schema": data.get("schema_version", "cloud_governance_recommendations.v1"),
        "total_recommendations": len(recommendations),
        "by_pillar": by_pillar,
        "by_provider": by_provider,
        "estimated_monthly_savings_usd": round(savings, 2),
        "top_savings_opportunities": [
            {
                "recommendation_id": r.get("recommendation_id"),
                "title": r.get("title"),
                "provider": r.get("provider"),
                "category": r.get("category"),
                "estimated_monthly_savings_usd": r.get("estimated_monthly_savings_usd"),
                "confidence": r.get("confidence"),
                "evidence_tier": r.get("evidence_tier"),
            }
            for r in top_savings
        ],
        "recommendations": recommendations,
        "limitations": list(data.get("limitations") or [])
        + [
            "Cloud recommendations are advisory — not auto-remediation.",
            "Mock data — connect Azure/GCP APIs behind interfaces for production.",
        ],
    }
    return attach_governance_envelope(payload, limitations=payload["limitations"])


def format_cloud_summary_markdown(summary: dict[str, Any]) -> str:
    """Render cloud governance summary as Markdown."""
    lines = [
        "# Cloud Governance Recommendations Summary",
        "",
        f"**Total recommendations:** {summary.get('total_recommendations', 0)}",
        f"**Estimated monthly savings (illustrative):** ${summary.get('estimated_monthly_savings_usd', 0):.2f}",
        "",
        "## By pillar",
        "",
    ]
    for pillar, count in sorted((summary.get("by_pillar") or {}).items()):
        label = _PILLAR_LABELS.get(pillar, pillar.replace("_", " ").title())
        lines.append(f"- {label}: {count}")
    lines.extend(["", "## Top savings opportunities", ""])
    for row in summary.get("top_savings_opportunities") or []:
        lines.append(
            f"- **{row.get('recommendation_id')}** ({row.get('provider')}): "
            f"{row.get('title')} — ${float(row.get('estimated_monthly_savings_usd') or 0):.2f}/mo"
        )
    lines.extend(["", "## Limitations", ""])
    for lim in summary.get("limitations") or []:
        lines.append(f"- {lim}")
    return "\n".join(lines) + "\n"
