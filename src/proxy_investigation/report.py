"""Structured incident report (markdown) from investigation result.

Module responsibility:
    Render operator-facing markdown separating observations, evidence, hypotheses,
    validation, remediation previews, and explicit limitations.

System placement:
    Invoked by ``workflow`` after ``ProxyInvestigationResult`` is assembled.

Output guarantees:
    Plain-text markdown string; no file I/O (caller may write to ``reports/proxy_investigations``).

Side effects:
    None.

Audit Notes:
    * Report repeats ``MALWARE_FORBIDDEN`` and ``ATTRIBUTION_LISTENER_ONLY`` in limitations section.
"""

from __future__ import annotations

from .constants import ATTRIBUTION_LISTENER_ONLY, MALWARE_FORBIDDEN
from .models import ProxyInvestigationResult


def render_incident_report(result: ProxyInvestigationResult) -> str:
    """Generate operator-facing incident report with evidence boundaries.

    Args:
        result: Completed investigation run with observations and hypotheses populated.

    Returns:
        Markdown string suitable for console output or ``reports/proxy_investigations/*.md``.

    Side effects:
        None.
    """
    lines = [
        "PROXY DRIFT INVESTIGATION REPORT",
        "=" * 72,
        "",
        "## Context",
        f"Run ID: {result.run_id}",
        f"Timestamp (UTC): {result.timestamp}",
        f"Schema: {result.schema_version}",
        "Scenario: unexplained localhost WinINET proxy drift (Node/Electron/dev tooling may be present).",
        "",
        "## Observations",
    ]
    for o in result.observations:
        lines.append(f"- [{o.category}] {o.summary}")

    lines.extend(["", "## Evidence", "### Proxy configuration"])
    p = result.proxy_snapshot
    lines.append(f"- Registry: `{p.get('registry_path')}`")
    lines.append(f"- ProxyEnable: {p.get('proxy_enable')}")
    lines.append(f"- ProxyServer: {p.get('proxy_server')!r}")
    lines.append(f"- AutoConfigURL: {p.get('auto_config_url')!r}")
    lines.append(f"- WinHTTP direct: {p.get('winhttp', {}).get('direct_access')}")
    env = p.get("environment") or {}
    if any(env.values()):
        lines.append(f"- Environment proxies: {env}")

    lines.extend(["", "### Listener / process correlation"])
    lb = result.listener_evidence.get("localhost_attribution") or {}
    if lb.get("listener_found"):
        for owner in lb.get("owners") or []:
            if isinstance(owner, dict):
                lines.append(
                    f"- Listener: pid={owner.get('pid')} name={owner.get('process_name')!r} "
                    f"parent={owner.get('parent_name')!r}"
                )
    else:
        lines.append("- No listener correlated on configured localhost port.")

    dev_rows = result.dev_process_evidence.get("dev_process_rows") or []
    if dev_rows:
        lines.extend(["", "### Developer-tooling processes (association only)"])
        for row in dev_rows[:8]:
            if isinstance(row, dict):
                lines.append(
                    f"- {row.get('process_name')} pid={row.get('pid')} "
                    f"path={row.get('executable_path')!r}"
                )

    if result.before_snapshot:
        lines.extend(
            [
                "",
                "### Before snapshot (drift reference)",
                f"- Prior ProxyEnable: {result.before_snapshot.get('proxy_enable')}",
                f"- Prior ProxyServer: {result.before_snapshot.get('proxy_server')!r}",
            ],
        )

    lines.extend(["", "## State assessment"])
    pa = result.path_assessment or {}
    if pa:
        lines.append(f"- Composite path state: {pa.get('composite_state')}")
        lines.append(f"- Summary: {pa.get('human_summary', '')}")
    else:
        lines.append("- Path assessment not available.")

    lines.extend(["", "## Hypotheses (ordinal — not probability)"])
    for h in result.hypotheses[:6]:
        lines.append(f"- **{h.hypothesis_id}** [{h.confidence}]: {h.title}")
        for ev in h.evidence_for[:3]:
            lines.append(f"    + {ev}")

    lines.extend(["", "## Competing hypotheses"])
    for c in result.competing_hypotheses:
        lines.append(f"- {c}")

    lines.extend(
        [
            "",
            f"**Primary hypothesis:** {result.primary_hypothesis_id}",
            f"**Confidence boundary:** {result.confidence_boundary}",
            "",
            "## Verification results",
        ],
    )
    v = result.validation
    lines.append(f"- DNS: {v.get('dns_ok')}")
    lines.append(f"- TCP 443: {v.get('tcp_443_ok')}")
    lines.append(f"- HTTPS: {v.get('https_ok')}")
    lines.append(f"- HTTPS via proxy path: {v.get('proxied_https_ok')}")
    lines.append(f"- HTTPS bypass (--noproxy): {v.get('proxy_bypass_https_ok')}")

    lines.extend(
        [
            "",
            "## Verification strategy",
        ],
    )
    for step in result.verification_strategy:
        lines.append(f"- {step}")

    lines.extend(
        [
            "",
            "## Attribution boundary",
            f"- Status: **{result.attribution_status}**",
        ],
    )
    for note in result.attribution_notes:
        lines.append(f"- {note}")
    lines.append(f"- {ATTRIBUTION_LISTENER_ONLY}")
    lines.append(f"- {MALWARE_FORBIDDEN}")

    lines.extend(["", "## Risk assessment"])
    ra = result.risk_assessment
    lines.append(f"- Operational risk: {ra.get('operational_risk', 'unknown')}")
    lines.append(f"- Classification hint: {ra.get('classification_hint', 'unknown')}")

    lines.extend(["", "## Remediation preview (no auto-execution)"])
    for r in result.remediation_previews:
        lines.append(f"- [{r.policy}] {r.title}: {r.detail}")
        if r.command_preview:
            lines.append(f"    Preview: `{r.command_preview}`")

    lines.extend(["", "## Limitations"])
    for lim in result.limitations:
        lines.append(f"- {lim}")

    return "\n".join(lines)
