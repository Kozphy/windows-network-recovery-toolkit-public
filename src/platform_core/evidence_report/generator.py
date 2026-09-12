"""Evidence Timeline & Report Engine — JSONL, Markdown, HTML."""

from __future__ import annotations

import json
from typing import Any, Literal

from .confidence_model import build_confidence_entries

ReportFormat = Literal["json", "jsonl", "markdown", "html"]


def generate_evidence_report(package: dict[str, Any], *, fmt: ReportFormat = "markdown") -> str:
    """Return generate evidence report.

    Args:
        package: package supplied by the caller.
        fmt: fmt supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    confidence = [e.to_dict() for e in build_confidence_entries(package)]
    sections = {
        "incident_id": package.get("incident_id"),
        "executive_summary": package.get("executive_summary", ""),
        "confidence_model": confidence,
        "timeline": package.get("timeline", []),
        "proxy_writer_attribution": package.get("proxy_writer_attribution"),
        "tls_proof": package.get("tls_proof"),
        "website_risk": package.get("website_risk"),
        "proof_results": package.get("proof_results"),
        "safety_notes": package.get("safety_notes", [
            "This is an evidence and risk toolkit — not antivirus or phishing protection.",
            "No silent remediation; preview mode by default.",
        ]),
        "disclaimer": (
            "Endpoint Network Evidence & Risk Toolkit provides observability and structured "
            "evidence for IT/security review. It does not replace endpoint protection products."
        ),
    }

    if fmt == "json":
        return json.dumps(sections, indent=2)

    if fmt == "jsonl":
        lines = [json.dumps({"type": "header", **{k: sections[k] for k in ("incident_id", "executive_summary", "disclaimer")}})]
        for entry in sections["timeline"]:
            lines.append(json.dumps({"type": "timeline", **entry}))
        for row in confidence:
            lines.append(json.dumps({"type": "confidence", **row}))
        return "\n".join(lines) + "\n"

    if fmt == "html":
        body = "<h1>Endpoint Network Evidence &amp; Risk Report</h1>"
        body += f"<p><em>{sections['disclaimer']}</em></p>"
        body += f"<p>{sections['executive_summary']}</p>"
        body += "<h2>Confidence Model</h2><table border='1'><tr><th>Phase</th><th>Subject</th><th>Statement</th><th>Confidence</th><th>Limitation</th><th>Action</th></tr>"
        for row in confidence:
            body += (
                f"<tr><td>{row['phase']}</td><td>{row['subject']}</td>"
                f"<td>{row['statement']}</td><td>{row['confidence']}</td>"
                f"<td>{row['limitation']}</td><td>{row['recommended_action']}</td></tr>"
            )
        body += "</table>"
        body += "<h2>Timeline</h2><pre>" + json.dumps(sections["timeline"], indent=2) + "</pre>"
        return f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Evidence Report</title></head><body>{body}</body></html>"

    lines = [
        "# Endpoint Network Evidence & Risk Report",
        "",
        f"**Disclaimer:** {sections['disclaimer']}",
        "",
        "## Executive Summary",
        str(sections["executive_summary"]),
        "",
        "## Confidence Model",
        "| Phase | Subject | Confidence | Limitation | Recommended Action |",
        "|-------|---------|------------|------------|-------------------|",
    ]
    for row in confidence:
        lines.append(
            f"| {row['phase']} | {row['subject']} | {row['confidence']} | "
            f"{row['limitation'][:60]} | {row['recommended_action'][:60]} |"
        )
    lines.extend([
        "",
        "## Timeline",
        "```json",
        json.dumps(sections["timeline"], indent=2),
        "```",
        "",
        "## TLS Proof",
        json.dumps(sections.get("tls_proof") or {}, indent=2),
        "",
        "## Website Risk",
        json.dumps(sections.get("website_risk") or {}, indent=2),
        "",
        "## Safety Notes",
    ])
    for note in sections["safety_notes"]:
        lines.append(f"- {note}")
    return "\n".join(lines)
