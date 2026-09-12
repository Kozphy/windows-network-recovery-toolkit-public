"""Executive risk report for home/SOHO LAN privacy analytics.

Module responsibility:
    Assemble cross-cutting executive JSON/Markdown from inventory, classification,
    risk score, controls, segmentation advice, and optional router correlation.

System placement:
    Invoked by ``lan_privacy.runner.run_executive_report_pipeline`` and executive CLI.

Key invariants:
    * Reuses ``report`` wording validators — same safe-language constraints apply.
    * Control gaps and unknown-vendor counts are factual tallies, not legal findings.
    * External domains sourced from correlation or explicit caller input only.

Side effects:
    * May write report files when ``write_executive_report`` is called by the runner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.platform_core.governance.report_sections import NON_CLAIMS

from .report import REQUIRED_SAFE_PHRASES, validate_report_wording


def build_executive_report(
    *,
    inventory: dict[str, Any],
    observations: list[dict[str, Any]],
    classification: dict[str, Any],
    risk_score: dict[str, Any],
    control_results: list[dict[str, Any]],
    segmentation_advice: list[dict[str, Any]],
    correlation: dict[str, Any] | None = None,
    external_domains: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble a cross-cutting executive JSON report with all required sections.

    Combines inventory, observations, classification, risk score, control results,
    segmentation advice, and optional router correlation into a governance-ready
    artifact tagged ``wnt.lan_executive.v1``.

    Args:
        inventory: Device inventory dict (from ``collect_inventory``).
        observations: Flat list of LAN observation dicts.
        classification: ``ClassificationResult.to_dict()`` output.
        risk_score: ``PrivacyRiskScoreResult.to_dict()`` output.
        control_results: List of control-test result dicts (may be empty).
        segmentation_advice: List of ``SegmentationAdvice.to_dict()`` entries.
        correlation: Optional router-host correlation dict from
            ``correlate_host_router``.
        external_domains: Optional explicit list of external domain strings observed.
            Falls back to matched DNS domains from ``correlation`` when ``None``.

    Returns:
        JSON-serializable executive report dict with ``executive_summary``,
        ``key_findings``, ``control_gaps``, ``segmentation_advice``,
        ``what_tool_cannot_prove``, and other governance sections.
    """
    unknown = [
        d for d in (inventory.get("devices") or []) if "unknown_vendor" in (d.get("flags") or [])
    ]
    gaps = [c for c in control_results if c.get("test_result") in {"FAIL", "PARTIAL"}]

    from collections import Counter

    probe_counts: Counter[str] = Counter()
    for o in observations:
        src = o.get("source_ip") or o.get("client_ip") or "unknown"
        probe_counts[src] += 1

    domains = external_domains or []
    if not domains and correlation:
        domains = list(
            {e.get("domain") for e in correlation.get("matched_dns") or [] if e.get("domain")}
        )

    return {
        "schema_version": "wnt.lan_executive.v1",
        "report_type": "risk_executive_report",
        "executive_summary": (
            f"Technology Risk / Control Analytics summary for home/SOHO LAN privacy. "
            f"Classification: {classification.get('primary_classification')}. "
            f"Privacy risk score: {risk_score.get('numeric_score')} ({risk_score.get('risk_level')}). "
            f"Observed local network discovery activity — not a security verdict."
        ),
        "key_findings": [
            f"Primary classification: {classification.get('primary_classification')}",
            f"Evidence sources: {', '.join(risk_score.get('evidence_sources_present') or [])}",
            f"Devices inventoried: {len(inventory.get('devices') or [])}",
            f"Unknown-vendor devices: {len(unknown)}",
        ],
        "evidence_tier": risk_score.get("evidence_tier"),
        "evidence_sources_present": risk_score.get("evidence_sources_present") or [],
        "top_probing_devices": [
            {"source": k, "event_count": v} for k, v in probe_counts.most_common(5)
        ],
        "unknown_devices": unknown,
        "external_domains_observed": domains
        if domains
        else ["not available — import router DNS logs"],
        "control_gaps": gaps,
        "control_results": control_results,
        "segmentation_advice": segmentation_advice,
        "recommended_next_steps": _executive_steps(gaps, classification, risk_score),
        "what_tool_can_prove": [
            "Observed local network discovery and neighbor inventory from Windows host.",
            "Correlated router DNS/DHCP evidence when imported.",
            "Control test pass/fail against defined CTRL-LAN objectives.",
        ],
        "what_tool_cannot_prove": NON_CLAIMS
        + [
            "Cannot confirm spying, data theft, malware, or advertising surveillance.",
            "Cannot confirm data exfiltration from Windows host telemetry alone.",
            "Scanning activity is not confirmed malicious intent.",
            "Requires router-level or packet-capture evidence for cross-host attribution.",
        ],
        "classification": classification,
        "risk_score": risk_score,
        "limitations": classification.get("limitations") or [],
    }


def _executive_steps(
    gaps: list[dict[str, Any]],
    classification: dict[str, Any],
    risk_score: dict[str, Any],
) -> list[str]:
    steps = [
        "Consider (preview only): Review executive findings with household or SOHO IT owner.",
        "Consider (preview only): Import router DNS/DHCP logs for stronger outbound visibility.",
    ]
    for g in gaps[:3]:
        steps.append(
            f"Consider (preview only): Address {g.get('control_id')} — {g.get('recommendation', '')[:80]}"
        )
    if risk_score.get("human_review_recommended"):
        steps.append("Consider (preview only): Human review recommended for elevated privacy risk.")
    return steps


def render_executive_markdown(report: dict[str, Any]) -> str:
    """Render an executive report dict as a Markdown document.

    Enforces ``REQUIRED_SAFE_PHRASES`` at the end of the document when not
    already present.  Sections include executive summary, key findings, evidence
    tier, top probing devices, unknown devices, external domains, control gaps,
    recommended next steps, and cannot-prove statements.

    Args:
        report: Dict produced by ``build_executive_report``.

    Returns:
        Markdown string for ``risk_executive_report.md``.
    """
    lines = [
        "# LAN Technology Risk — Executive Report",
        "",
        "## Executive summary",
        report.get("executive_summary", ""),
        "",
        "## Key findings",
    ]
    for f in report.get("key_findings") or []:
        lines.append(f"- {f}")
    lines.extend(
        [
            "",
            "## Evidence tier",
            f"- **Tier:** {report.get('evidence_tier')}",
            f"- **Sources:** {', '.join(report.get('evidence_sources_present') or [])}",
            "",
            "## Top probing devices",
        ]
    )
    for item in report.get("top_probing_devices") or []:
        lines.append(f"- {item.get('source')}: {item.get('event_count')} events")
    lines.extend(["", "## Unknown devices"])
    for d in report.get("unknown_devices") or []:
        lines.append(f"- {d.get('ip')} — {d.get('mac')}")
    if not report.get("unknown_devices"):
        lines.append("- None")
    lines.extend(["", "## External domains observed"])
    for dom in report.get("external_domains_observed") or []:
        lines.append(f"- {dom}")
    lines.extend(["", "## Control gaps"])
    for g in report.get("control_gaps") or []:
        lines.append(
            f"- **{g.get('control_id')}**: {g.get('test_result')} — {g.get('objective', '')[:60]}"
        )
    if not report.get("control_gaps"):
        lines.append("- No FAIL/PARTIAL controls in this assessment")
    lines.extend(["", "## Recommended next steps (preview only)"])
    for s in report.get("recommended_next_steps") or []:
        lines.append(f"- {s}")
    lines.extend(["", "## What this tool can prove"])
    for p in report.get("what_tool_can_prove") or []:
        lines.append(f"- {p}")
    lines.extend(["", "## What this tool cannot prove"])
    for p in report.get("what_tool_cannot_prove") or []:
        lines.append(f"- {p}")
    lines.append("")
    lines.append(
        "Observed local network discovery activity — requires additional evidence for attribution."
    )
    lines.append("Cannot confirm data exfiltration from Windows host telemetry alone.")
    text = "\n".join(lines)
    for phrase in REQUIRED_SAFE_PHRASES:
        if phrase not in text.lower():
            text += f"\n\n_{phrase}_"
    return text


def write_executive_report(
    report: dict[str, Any],
    *,
    out_dir: str,
    fmt: str = "both",
) -> dict[str, str]:
    """Write executive report JSON and/or Markdown files to a directory.

    Validates Markdown output against ``FORBIDDEN_LAN_PHRASES`` and annotates
    the report with ``_wording_warnings`` when violations are found.

    Args:
        report: Dict produced by ``build_executive_report``.
        out_dir: Target directory path (created if absent).
        fmt: ``"json"``, ``"markdown"``, or ``"both"``.

    Returns:
        Dict mapping format keys (``"json"``, ``"markdown"``) to written file
        path strings.
    """
    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    if fmt in {"json", "both"}:
        import json

        jp = path / "risk_executive_report.json"
        jp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        written["json"] = str(jp)
    if fmt in {"markdown", "both"}:
        md = render_executive_markdown(report)
        violations = validate_report_wording(md)
        if violations:
            report["_wording_warnings"] = violations
        mp = path / "risk_executive_report.md"
        mp.write_text(md, encoding="utf-8")
        written["markdown"] = str(mp)
    return written
