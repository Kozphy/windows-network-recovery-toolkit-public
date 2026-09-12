"""Markdown and JSON formatters for final causation reports."""

from __future__ import annotations

from typing import Any

from src.proxy_guard.final_causation import FinalCausationReport


def render_final_causation_markdown(report: FinalCausationReport) -> str:
    """Render sections A–J for operator review."""
    lines: list[str] = []
    lines.append("# Proxy Final Causation Report")
    lines.append("")
    lines.append("## A. Executive Summary")
    lines.append(f"- **Verdict:** `{report.verdict}`")
    lines.append(f"- **Confidence:** {report.confidence:.2f}")
    lines.append(f"- **Proof level:** `{report.proof_level}`")
    lines.append(f"- {report.root_cause_sentence}")
    lines.append("")
    lines.append("## B. Current Proxy State")
    for key, val in sorted(report.current_proxy_state.items()):
        lines.append(f"- `{key}`: {val!r}")
    lines.append("")
    lines.append("## C. Timeline of Proxy Changes")
    for row in report.timeline:
        lines.append(f"- {row}")
    lines.append("")
    lines.append("## D. Proven Registry Writer Evidence")
    writes = report.evidence_tree.get("registry_writes") or []
    if writes:
        for w in writes:
            lines.append(
                f"- [{w.get('proof_level')}] {w.get('timestamp_utc')} "
                f"{w.get('image')} → {w.get('registry_value_name')} = {w.get('written_value')}"
            )
    else:
        lines.append("- No registry write proof collected (Sysmon Event ID 13 unavailable).")
    lines.append("")
    lines.append("## E. Process Tree")
    tree = report.evidence_tree.get("process_tree") or {}
    for node in tree.get("chain") or []:
        lines.append(f"- {node.get('image') or node.get('process_name')} (pid={node.get('process_id')})")
    if not tree.get("chain"):
        lines.append("- Process tree unavailable.")
    lines.append("")
    lines.append("## F. Localhost Port Owner")
    po = report.evidence_tree.get("port_owner")
    if po:
        lines.append(
            f"- {po.get('process_name')} pid={po.get('process_id')} "
            f"listening on {po.get('local_address')}:{po.get('local_port')}"
        )
    else:
        lines.append("- Port owner not resolved.")
    lines.append("")
    lines.append("## G. Browser/Network Path Proof")
    pp = report.evidence_tree.get("path_proof") or {}
    lines.append(f"- Direct path OK: {pp.get('direct_path_ok')}")
    lines.append(f"- Proxied path OK: {pp.get('proxied_path_ok')}")
    lines.append(f"- Bypass path OK: {pp.get('bypass_path_ok')}")
    lines.append(f"- Failure mode: `{pp.get('failure_mode')}`")
    lines.append(f"- {pp.get('evidence_summary')}")
    lines.append("")
    lines.append("## H. Final Verdict")
    lines.append(f"**{report.verdict}** — {report.root_cause_sentence}")
    lines.append("")
    lines.append("## I. What is proven vs what is only likely")
    for key, val in report.proven_vs_likely.items():
        lines.append(f"- **{key}:** {val}")
    lines.append("")
    lines.append("## J. Safe next actions")
    for action in report.recommended_next_action:
        lines.append(f"- {action}")
    lines.append("")
    lines.append("### Safe operator commands (read-only)")
    for cmd in report.safe_operator_commands:
        lines.append("```")
        lines.append(cmd)
        lines.append("```")
    lines.append("")
    lines.append(
        "_Observation is not proof. Correlation is not causation. "
        "Only Sysmon/ETW/Event Log registry-write evidence upgrades a suspect to proven writer._"
    )
    return "\n".join(lines)


def render_final_causation_json(report: FinalCausationReport) -> dict[str, Any]:
    """JSON export bundle."""
    return report.to_dict()
