"""Compute attribution level from observation, correlation, and proof evidence."""

from __future__ import annotations

from typing import Any

from ..core.time_utils import utc_now_iso
from .attribution_model import AttributionEvidence
from .investigation_models import (
    AttributionConclusion,
    AttributionLevel,
    InvestigationEvidenceItem,
)
from .process_tree import build_process_chain_nodes
from .proxy_allowlist import ProxyAllowlist, allowlist_match_summary


def _cmdline_proxy_terms(cmdline: str | None) -> bool:
    if not cmdline:
        return False
    low = cmdline.lower()
    return any(t in low for t in ("proxy", "tunnel", "socks", "mitm", "mcp", "dev-server", "devserver"))


def compute_attribution_level(
    *,
    owner: dict[str, Any] | None,
    process_rows: list[dict[str, Any]],
    sysmon_events: list[AttributionEvidence],
    procmon_events: list[AttributionEvidence],
    matched_port: int | None,
    allowlist: ProxyAllowlist,
    timestamp_utc: str | None = None,
) -> AttributionConclusion:
    """Map evidence to AttributionLevel ladder."""
    ts = timestamp_utc or utc_now_iso()
    items: list[InvestigationEvidenceItem] = []
    limitations: list[str] = [
        "Listener correlation does not prove registry writer identity.",
        "Allowlist match reduces risk but does not prove authorization.",
    ]

    proven_sysmon = any(
        ev.source == "sysmon_event_13" and (ev.confidence_score or 0) >= 0.85 for ev in sysmon_events
    )
    proven_procmon = any(
        ev.source == "procmon_csv" and (ev.confidence_score or 0) >= 0.85 for ev in procmon_events
    )
    if proven_sysmon or proven_procmon:
        proof_ev = sysmon_events[0] if proven_sysmon else procmon_events[0]
        excerpt = proof_ev.raw_excerpt or {}
        suspect = str(excerpt.get("image") or excerpt.get("process_name") or "unknown")
        pid_raw = excerpt.get("process_id") or excerpt.get("pid")
        pid = int(pid_raw) if isinstance(pid_raw, int) else None
        source = "sysmon_event_13" if proven_sysmon else "procmon_csv"
        items.append(
            InvestigationEvidenceItem(
                evidence_type="registry_write_proof",
                source=source,
                strength="proof",
                description=f"Registry write on WinINET proxy key observed via {source}.",
                timestamp_utc=ts,
                limitations=("Proof tier requires corroborating export retention for audits.",),
                detail={"raw_excerpt": excerpt},
            )
        )
        return AttributionConclusion(
            level=AttributionLevel.PROVEN_REGISTRY_WRITER,
            suspect_process=suspect.split("\\")[-1] if suspect else None,
            suspect_pid=pid,
            parent_chain=(),
            evidence_items=tuple(items),
            limitations=tuple(limitations),
            conclusion_text=(
                "Registry writer proven via Sysmon Event ID 13 or Procmon RegSetValue export."
                if proven_sysmon
                else "Registry writer proven via Procmon CSV RegSetValue on Internet Settings."
            ),
        )

    if not owner or owner.get("pid") is None:
        if any(ev.source == "unknown" for ev in sysmon_events):
            limitations.append("Sysmon unavailable: registry writer cannot be proven.")
        return AttributionConclusion(
            level=AttributionLevel.NONE,
            suspect_process=None,
            suspect_pid=None,
            parent_chain=(),
            evidence_items=tuple(items),
            limitations=tuple(limitations),
            conclusion_text="No listener owner resolved; attribution remains at observation tier.",
        )

    pid = int(owner["pid"])
    pname = str(owner.get("process_name") or "unknown")
    listener_match = bool(owner.get("listener_on_proxy_port"))
    cmd_terms = _cmdline_proxy_terms(str(owner.get("command_line") or ""))
    chain_nodes = build_process_chain_nodes(
        focus_pid=pid, process_rows=process_rows, matched_port=matched_port
    )
    parent_chain = tuple(str(n.get("process_name") or "unknown") for n in chain_nodes)

    if listener_match and matched_port:
        items.append(
            InvestigationEvidenceItem(
                evidence_type="localhost_listener",
                source="netstat_owner",
                strength="medium",
                description=f"Process listens on 127.0.0.1:{matched_port} matching ProxyServer port.",
                timestamp_utc=ts,
            )
        )
    if cmd_terms:
        items.append(
            InvestigationEvidenceItem(
                evidence_type="command_line_keyword",
                source="cim_process",
                strength="weak",
                description="Command line contains proxy/dev-related keywords.",
                timestamp_utc=ts,
            )
        )
    allow = allowlist_match_summary(
        process_name=pname,
        executable_path=str(owner.get("executable_path") or ""),
        command_line=str(owner.get("command_line") or ""),
        allowlist=allowlist,
    )
    if allow.get("any_match"):
        items.append(
            InvestigationEvidenceItem(
                evidence_type="allowlist_match",
                source="config/proxy_allowlist.yaml",
                strength="weak",
                description="Process matched trusted allowlist (risk downgrade only).",
                timestamp_utc=ts,
                detail=allow,
            )
        )

    if any(ev.source == "unknown" for ev in sysmon_events):
        limitations.append("Sysmon unavailable: registry writer cannot be proven.")
    elif sysmon_events and all((ev.confidence_score or 0) < 0.85 for ev in sysmon_events):
        limitations.append("No Sysmon Event ID 13 found within correlation window.")

    level = AttributionLevel.CANDIDATE
    if listener_match:
        level = AttributionLevel.CORRELATED
    parent_count = len(parent_chain)
    if listener_match and (cmd_terms or parent_count >= 2):
        level = AttributionLevel.STRONG_CORRELATION

    if allow.get("any_match") and level == AttributionLevel.STRONG_CORRELATION:
        conclusion = (
            "This is consistent with Cursor/dev tooling creating a local proxy, "
            "but registry writer is not proven."
        )
    elif level in {AttributionLevel.CORRELATED, AttributionLevel.STRONG_CORRELATION}:
        conclusion = (
            "Listener correlation suggests a candidate process; registry writer remains unproven."
        )
    else:
        conclusion = "Insufficient correlation for strong attribution."

    return AttributionConclusion(
        level=level,
        suspect_process=pname,
        suspect_pid=pid,
        parent_chain=parent_chain,
        evidence_items=tuple(items),
        limitations=tuple(dict.fromkeys(limitations)),
        conclusion_text=conclusion,
    )
