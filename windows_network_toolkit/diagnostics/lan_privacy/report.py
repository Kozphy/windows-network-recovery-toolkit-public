"""LAN privacy report — JSON and Markdown with safe wording.

Module responsibility:
    Build structured reports and Markdown narratives with forbidden-phrase filtering
    and required safe-language guardrails.

System placement:
    Used by ``lan_privacy.runner`` and ``executive_report``; output of ``lan-privacy-report`` CLI.

Key invariants:
    * ``FORBIDDEN_LAN_PHRASES`` and ``REQUIRED_SAFE_PHRASES`` enforced before render.
    * Explanations pass through ``sanitize_explanation_text`` where applicable.
    * Reports include ``NON_CLAIMS`` and ``LAN_LIMITATIONS`` — no covert surveillance claims.

Side effects:
    * None — string and dict assembly only.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from src.platform_core.ai_risk_analyst.explanation_guardrails import sanitize_explanation_text
from src.platform_core.governance.report_sections import NON_CLAIMS

from .models import LAN_LIMITATIONS, SCHEMA_VERSION
from .privacy_risk_score import PrivacyRiskScoreResult

FORBIDDEN_LAN_PHRASES = frozenset(
    {
        "confirmed spying",
        "stealing data",
        "confirmed malware",
        "confirmed smart tv tracking",
        "confirmed advertising surveillance",
        "data harvesting confirmed",
    }
)

REQUIRED_SAFE_PHRASES = [
    "observed local network discovery activity",
    "cannot confirm data exfiltration from Windows host telemetry alone",
]


def _top_probing_devices(
    observations: list[dict[str, Any]], limit: int = 5
) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for o in observations:
        src = o.get("source_ip") or o.get("source_mac") or "unknown"
        counts[src] += 1
    return [{"source": k, "event_count": v} for k, v in counts.most_common(limit)]


def _protocol_summary(observations: list[dict[str, Any]]) -> dict[str, int]:
    c: Counter[str] = Counter()
    for o in observations:
        c[o.get("protocol", "UNKNOWN")] += 1
    return dict(c)


def _recommended_steps(classification: str, score: PrivacyRiskScoreResult) -> list[str]:
    steps = [
        "Consider (preview only): Review router DHCP client list against observed inventory.",
        "Consider (preview only): Enable router DNS logging if outbound IoT activity is a concern.",
    ]
    if classification in {"BROAD_SUBNET_PROBING", "POSSIBLE_LATERAL_RECON"}:
        steps.append(
            "Consider (preview only): Investigate repeated subnet probing — "
            "requires router-level or packet-capture evidence."
        )
    if score.human_review_recommended:
        steps.append(
            "Consider (preview only): Escalate for human review — elevated privacy risk score."
        )
    return steps


def validate_report_wording(text: str) -> list[str]:
    """Check report text for forbidden accusatory phrases.

    Args:
        text: Report string to validate (markdown or plain text).

    Returns:
        List of forbidden phrases found in the text (empty list when all-clear).
        Consumers should block or flag reports containing any found phrase.
    """
    lower = text.lower()
    return [p for p in FORBIDDEN_LAN_PHRASES if p in lower]


def build_lan_privacy_report(
    *,
    inventory: dict[str, Any],
    observations: list[dict[str, Any]],
    classification: dict[str, Any],
    risk_score: PrivacyRiskScoreResult | dict[str, Any],
    timeline: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a tactical LAN privacy report as a JSON-serializable dict.

    Assembles device inventory, protocol summary, top-probing-device tallies,
    unknown-device list, classification result, risk score, recommended next
    steps, ``LAN_LIMITATIONS``, and ``NON_CLAIMS`` into a single structured
    report artifact.

    Args:
        inventory: Device inventory dict (from ``collect_inventory``).
        observations: Flat list of ``LanObservation`` dicts.
        classification: ``ClassificationResult.to_dict()`` output.
        risk_score: ``PrivacyRiskScoreResult`` instance or equivalent dict.
        timeline: Optional ordered list of observation events for the timeline
            section.  Defaults to the first 100 observations.

    Returns:
        JSON-serializable dict tagged ``SCHEMA_VERSION`` with all required
        sections and safe-language guardrails applied.
    """
    score_dict = risk_score.to_dict() if hasattr(risk_score, "to_dict") else risk_score
    devices = inventory.get("devices") or []
    unknown = [d for d in devices if "unknown_vendor" in (d.get("flags") or [])]

    report = {
        "schema_version": SCHEMA_VERSION,
        "report_type": "lan_privacy_report",
        "executive_summary": sanitize_explanation_text(
            f"Observed local network discovery activity across {len(devices)} inventoried devices. "
            f"Primary classification: {classification.get('primary_classification', 'UNKNOWN')}. "
            f"Privacy risk score: {score_dict.get('numeric_score')} ({score_dict.get('risk_level')})."
        ),
        "timeline": timeline or observations[:100],
        "inventory": devices,
        "protocol_summary": _protocol_summary(observations),
        "top_probing_devices": _top_probing_devices(observations),
        "unknown_devices": unknown,
        "classification": classification,
        "risk_score": score_dict,
        "recommended_next_steps": _recommended_steps(
            classification.get("primary_classification", ""),
            risk_score
            if hasattr(risk_score, "human_review_recommended")
            else PrivacyRiskScoreResult(
                numeric_score=score_dict.get("numeric_score", 0),
                risk_level=score_dict.get("risk_level", "LOW"),
                evidence_tier=score_dict.get("evidence_tier", "T0_OBSERVATION"),
                components=score_dict.get("components", {}),
                explanation=score_dict.get("explanation", ""),
            ),
        ),
        "limitations": list(LAN_LIMITATIONS) + list(classification.get("limitations") or []),
        "non_claims": NON_CLAIMS
        + [
            "This report does not confirm spying, data theft, malware, or advertising surveillance.",
            "Scanning activity is not confirmed malicious intent.",
        ],
    }
    return report


def render_lan_privacy_markdown(report: dict[str, Any]) -> str:
    """Render a LAN privacy report dict as a Markdown document.

    Applies mandatory safe-language guardrails: the output always contains at
    least one ``REQUIRED_SAFE_PHRASES`` occurrence.  Sections include executive
    summary, classification, risk score, protocol summary, top probing devices,
    unknown devices, recommended next steps, limitations, and non-claims.

    Args:
        report: Dict produced by ``build_lan_privacy_report``.

    Returns:
        Markdown string suitable for saving as ``lan_privacy_report.md``.
    """
    lines = [
        "# LAN Privacy Report",
        "",
        "## Executive summary",
        report.get("executive_summary", ""),
        "",
        "## Classification",
        f"- **Primary:** {report.get('classification', {}).get('primary_classification', '')}",
        f"- **Reasoning:** {report.get('classification', {}).get('reasoning', '')}",
        f"- **Evidence source:** {report.get('classification', {}).get('highest_evidence_source', '')}",
        "",
        "## Privacy risk score",
        f"- **Score:** {report.get('risk_score', {}).get('numeric_score')} ({report.get('risk_score', {}).get('risk_level')})",
        f"- **Tier:** {report.get('risk_score', {}).get('evidence_tier')}",
        "",
        "## Protocol summary",
    ]
    for proto, count in (report.get("protocol_summary") or {}).items():
        lines.append(f"- {proto}: {count}")
    lines.extend(["", "## Top probing devices (by event count)"])
    for item in report.get("top_probing_devices") or []:
        lines.append(f"- {item.get('source')}: {item.get('event_count')}")
    lines.extend(["", "## Unknown devices"])
    for d in report.get("unknown_devices") or []:
        lines.append(f"- {d.get('ip')} ({d.get('mac')})")
    if not report.get("unknown_devices"):
        lines.append("- None observed")
    lines.extend(["", "## Recommended next steps (preview only)"])
    for step in report.get("recommended_next_steps") or []:
        lines.append(f"- {step}")
    lines.extend(["", "## Limitations"])
    for lim in report.get("limitations") or []:
        lines.append(f"- {lim}")
    lines.extend(["", "## What this tool cannot prove"])
    for nc in report.get("non_claims") or []:
        lines.append(f"- {nc}")
    lines.extend(["", "---", "Observed local network discovery activity — not a security verdict."])
    lines.append("Cannot confirm data exfiltration from Windows host telemetry alone.")
    return "\n".join(lines)
