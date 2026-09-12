"""Unified read-only proxy investigation bundle for ``proxy-investigate`` CLI.

Combines WinINET/WinHTTP state, port ownership, evidence tiers, risk classification,
and policy recommendations without mutating system state.
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.models import registry_with_parsed
from ..core.time_utils import utc_now_iso
from ..version import SCRIPT_VERSION
from .attribution_levels import compute_attribution_level
from .flip_flop import detect_active_reverter
from .investigation_evidence import EvidenceLine, InvestigationEvidence
from .investigation_risk import InvestigationRisk, classify_investigation_risk
from .localhost_attribution import build_localhost_proxy_attribution
from .parser import parse_proxy_server
from .process_snapshot_enrichment import capture_enriched_process_snapshot
from .process_tree import (
    build_process_chain_nodes,
    render_process_tree_json,
    render_process_tree_text,
)
from .procmon_import import load_procmon_proxy_events
from .proxy_allowlist import allowlist_match_summary, load_proxy_allowlist
from .proxy_transitions import (
    build_recovery_guidance,
    load_recent_proxy_transitions,
    parse_since_duration,
    summarize_transition_row,
)
from .registry import read_proxy_registry
from .snapshot_capture import capture_proxy_snapshot
from .sysmon_attribution import collect_sysmon_proxy_events
from .sysmon_correlation import filter_sysmon_within_seconds_of_transition


def _primary_owner(attrib: dict[str, Any]) -> dict[str, Any] | None:
    owners = attrib.get("owners") or []
    if not owners:
        return None
    row = owners[0]
    if not isinstance(row, dict):
        return None
    port = attrib.get("localhost_port")
    return {
        "pid": row.get("pid"),
        "process_name": row.get("process_name"),
        "executable_path": row.get("executable_path"),
        "command_line": row.get("command_line"),
        "parent_pid": row.get("parent_pid"),
        "parent_name": row.get("parent_name"),
        "start_time": row.get("creation_time_utc") or row.get("start_time"),
        "listener_on_proxy_port": bool(attrib.get("listener_found")),
        "port": port,
        "path_missing": not bool(row.get("executable_path")),
        "path_user_writable": _is_user_writable_path(row.get("executable_path")),
        "parent_is_powershell": _norm(row.get("parent_name")) in {"powershell.exe", "pwsh.exe"},
        "parent_is_cmd": _norm(row.get("parent_name")) == "cmd.exe",
        "parent_is_ide": _norm(row.get("parent_name")) in {"cursor.exe", "code.exe"},
        "dev_tool_indicator": _is_dev_process(_norm(row.get("process_name"))),
        "security_tool_indicator": _is_security_tool(_norm(row.get("process_name"))),
        "cmdline_proxy_terms": _cmdline_has_proxy_terms(row.get("command_line")),
    }


def _cmdline_has_proxy_terms(cmdline: Any) -> bool:
    if not isinstance(cmdline, str) or not cmdline.strip():
        return False
    low = cmdline.lower()
    return any(t in low for t in ("proxy", "tunnel", "socks", "http-proxy", "mitm", "mcp", "dev-server", "dev server"))


def build_correlation_result(
    *,
    parsed_dict: dict[str, Any],
    owner: dict[str, Any] | None,
) -> dict[str, Any]:
    """Summarize Level-1 correlation signals (not registry writer proof)."""

    owner = owner or {}
    proc = _norm(owner.get("process_name"))
    _norm(owner.get("parent_name"))
    return {
        "listener_matches_proxy_port": bool(owner.get("listener_on_proxy_port")),
        "process_name": owner.get("process_name"),
        "process_class": (
            "node"
            if proc == "node.exe"
            else "python"
            if proc == "python.exe"
            else "powershell"
            if proc in {"powershell.exe", "pwsh.exe"}
            else "unknown"
            if not proc
            else proc
        ),
        "parent_name": owner.get("parent_name"),
        "parent_is_powershell": bool(owner.get("parent_is_powershell")),
        "parent_is_cmd": bool(owner.get("parent_is_cmd")),
        "parent_is_ide": bool(owner.get("parent_is_ide")),
        "command_line_proxy_terms": bool(owner.get("cmdline_proxy_terms")),
        "path_missing": bool(owner.get("path_missing")),
        "path_user_writable": bool(owner.get("path_user_writable")),
        "localhost_port": parsed_dict.get("localhost_port"),
        "proof_status": "CORRELATED" if owner.get("listener_on_proxy_port") else "OBSERVED_ONLY",
    }


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_user_writable_path(path: Any) -> bool:
    if not isinstance(path, str) or not path.strip():
        return False
    norm = path.strip().strip('"').lower().replace("/", "\\")
    return any(x in norm for x in ("\\appdata\\", "\\temp\\", "\\users\\", "\\downloads\\"))


def _is_dev_process(name: str) -> bool:
    return name in {"node.exe", "python.exe", "electron.exe", "npm.cmd", "pnpm.exe"}


def _is_security_tool(name: str) -> bool:
    return name in {"fiddler.exe", "charles.exe", "mitmproxy.exe", "proxifier.exe"}


def _build_evidence(
    *,
    proxy: dict[str, Any],
    parsed_dict: dict[str, Any],
    attrib: dict[str, Any],
    owner: dict[str, Any] | None,
    winhttp: dict[str, Any],
    attribution: Any | None = None,
) -> InvestigationEvidence:
    lines: list[EvidenceLine] = []
    observed: list[str] = []
    correlated: list[str] = []
    missing: list[str] = ["Registry writer identity (requires Sysmon/Procmon/ETW/EventLog)."]

    enable = proxy.get("proxy_enable")
    server = proxy.get("proxy_server")
    if enable == 1:
        msg = "WinINET proxy is enabled."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))
    else:
        msg = "WinINET proxy is disabled."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))

    if server:
        msg = f"ProxyServer is {server!r}."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))

    if parsed_dict.get("is_localhost_proxy") and parsed_dict.get("localhost_port"):
        port = parsed_dict["localhost_port"]
        host = parsed_dict.get("localhost_host") or "127.0.0.1"
        msg = f"ProxyServer points to {host}:{port}."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))

    if proxy.get("auto_config_url"):
        msg = f"AutoConfigURL is set: {proxy.get('auto_config_url')!r}."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))
    if proxy.get("proxy_override"):
        msg = f"ProxyOverride is set: {proxy.get('proxy_override')!r}."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))

    winhttp_err = winhttp.get("error")
    if winhttp.get("direct_access") is True:
        msg = "WinHTTP reports direct access (split-stack possible)."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))
    elif winhttp_err:
        msg = f"WinHTTP probe note: {winhttp_err}"
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))

    if owner and owner.get("pid") is not None:
        pname = owner.get("process_name") or "unknown"
        pid = owner.get("pid")
        port = owner.get("port")
        msg = f"A {pname} process (PID {pid}) is listening on 127.0.0.1:{port}."
        observed.append(msg)
        lines.append(EvidenceLine("OBSERVED", msg))
        if owner.get("listener_on_proxy_port"):
            cmsg = "The listener port matches the configured ProxyServer port."
            correlated.append(cmsg)
            lines.append(EvidenceLine("CORRELATED", cmsg))
        if owner.get("parent_is_powershell") or owner.get("parent_is_cmd"):
            cmsg = f"The parent process is {owner.get('parent_name') or 'unknown'}."
            correlated.append(cmsg)
            lines.append(EvidenceLine("CORRELATED", cmsg))
        elif owner.get("parent_name"):
            pmsg = f"Parent process is {owner.get('parent_name')} (PID {owner.get('parent_pid')})."
            observed.append(pmsg)
            lines.append(EvidenceLine("OBSERVED", pmsg))
        if owner.get("path_missing"):
            msg = "Executable path for the listener process is unknown."
            observed.append(msg)
            lines.append(EvidenceLine("OBSERVED", msg))
        for np in (
            "This does not prove the listener process wrote the WinINET registry keys.",
            "This does not prove malware.",
            "This does not prove Cursor.exe caused the change.",
        ):
            lines.append(EvidenceLine("NOT_PROVEN", np))
    elif parsed_dict.get("is_localhost_proxy"):
        missing.append("Listener on configured localhost port (no matching LISTEN row).")

    proof_status: str = "CORRELATED" if owner and owner.get("listener_on_proxy_port") else "OBSERVED_ONLY"
    if attribution is not None:
        level = getattr(attribution, "level", None)
        if level is not None and getattr(level, "value", "") == "PROVEN_REGISTRY_WRITER":
            proof_status = "PROVEN_BY_SYSMON"
        elif level is not None and getattr(level, "value", "") == "STRONG_CORRELATION":
            proof_status = "STRONGLY_CORRELATED"
    confidence = 0.65 if owner and owner.get("listener_on_proxy_port") else 0.4

    limitations = (
        "Registry writer proof requires Sysmon Event ID 13 or Procmon RegSetValue export.",
        "Listener ownership and process correlation are candidate evidence only.",
        "Sensitive localhost proxy posture does not imply compromise.",
    )

    return InvestigationEvidence(
        observed_signals=tuple(observed),
        correlated_signals=tuple(correlated),
        contradicting_signals=(),
        missing_evidence=tuple(missing),
        suspected_process=owner,
        listener_evidence=attrib,
        registry_evidence={
            "proxy_enable": enable,
            "proxy_server": server,
            "parsed_proxy": parsed_dict,
        },
        command_line_evidence={
            "command_line": owner.get("command_line") if owner else None,
            "proxy_terms_in_cmdline": bool(
                owner
                and isinstance(owner.get("command_line"), str)
                and any(t in owner["command_line"].lower() for t in ("proxy", "tunnel", "socks", "mitm", "mcp"))
            ),
        },
        parent_process_evidence={
            "parent_pid": owner.get("parent_pid") if owner else None,
            "parent_name": owner.get("parent_name") if owner else None,
            "parent_is_powershell": owner.get("parent_is_powershell") if owner else False,
            "parent_is_cmd": owner.get("parent_is_cmd") if owner else False,
            "parent_is_ide": owner.get("parent_is_ide") if owner else False,
        },
        startup_evidence={
            "hint": "Startup/scheduled-task scan not run in this command (use startup-audit when added).",
            "available": False,
        },
        proof_status=proof_status,  # type: ignore[arg-type]
        confidence=confidence,
        limitations=limitations,
        lines=tuple(lines),
    )


@dataclass(frozen=True)
class ProxyInvestigationBundle:
    """Structured read-only investigation result."""

    event_id: str
    timestamp_utc: str
    tool_version: str
    command: str
    action_type: str
    dry_run: bool
    policy_decision: str
    wininet: dict[str, Any]
    winhttp: dict[str, Any]
    parsed_proxy: dict[str, Any]
    port_owner: dict[str, Any] | None
    correlation: dict[str, Any]
    evidence: InvestigationEvidence
    risk: InvestigationRisk
    recommended_next_steps: tuple[str, ...]
    limitations: tuple[str, ...]
    process_snapshot: dict[str, Any]
    process_tree: dict[str, Any]
    process_tree_text: str
    attribution: dict[str, Any]
    evidence_table: tuple[dict[str, Any], ...]
    recent_transitions: tuple[dict[str, Any], ...]
    policy_recommendation: dict[str, Any]
    situation_interpretation: str
    active_reverter: dict[str, Any] | None

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
            "tool_version": self.tool_version,
            "command": self.command,
            "action_type": self.action_type,
            "dry_run": self.dry_run,
            "policy_decision": self.policy_decision,
            "before_state": None,
            "after_state": None,
            "wininet": self.wininet,
            "winhttp": self.winhttp,
            "parsed_proxy": self.parsed_proxy,
            "port_owner": self.port_owner,
            "correlation": self.correlation,
            "evidence": self.evidence.to_jsonable(),
            "evidence_table": list(self.evidence_table),
            "proof_status": self.evidence.proof_status,
            "risk": self.risk.to_jsonable(),
            "attribution": self.attribution,
            "process_snapshot": self.process_snapshot,
            "process_tree": self.process_tree,
            "process_tree_text": self.process_tree_text,
            "recent_transitions": list(self.recent_transitions),
            "policy_recommendation": self.policy_recommendation,
            "situation_interpretation": self.situation_interpretation,
            "active_reverter": self.active_reverter,
            "recommended_next_steps": list(self.recommended_next_steps),
            "limitations": list(self.limitations),
            "result": "success",
            "errors": [],
        }


def build_proxy_investigation_bundle(
    *,
    repo_root: Path | None = None,
    before_snapshot: dict[str, Any] | None = None,
    since_seconds: int | str | None = 1800,
    procmon_csv: str | None = None,
    run: Callable[..., Any] = subprocess.run,
) -> ProxyInvestigationBundle:
    """Collect read-only proxy investigation state (no mutations)."""

    lookback = parse_since_duration(since_seconds)
    root = repo_root or Path.cwd()

    if before_snapshot is None and repo_root is not None:
        from ..proxy_investigation.collectors import load_optional_before_snapshot

        before_snapshot = load_optional_before_snapshot(repo_root)

    reg = read_proxy_registry(run=run)
    parsed = parse_proxy_server(reg.proxy_server)
    merged = registry_with_parsed(reg, parsed)
    snap = capture_proxy_snapshot(registry_snapshot=reg, run=run)
    attrib = build_localhost_proxy_attribution(reg, parsed, run=run)
    owner = _primary_owner(attrib)
    parsed_dict = dict(merged.get("parsed_proxy") or parsed.to_dict())
    localhost_port = parsed_dict.get("localhost_port")

    process_snapshot = capture_enriched_process_snapshot(
        proxy_localhost_port=int(localhost_port) if localhost_port else None,
        run=run,
    )
    process_rows = process_snapshot.get("process_rows") or []

    allowlist = load_proxy_allowlist(root)
    allow_match = allowlist_match_summary(
        process_name=str(owner.get("process_name") or "") if owner else None,
        executable_path=str(owner.get("executable_path") or "") if owner else None,
        command_line=str(owner.get("command_line") or "") if owner else None,
        allowlist=allowlist,
    )

    recent = tuple(load_recent_proxy_transitions(root, since_seconds=lookback))
    flip_records: list[dict[str, Any]] = []
    for row in recent:
        diff = row.get("diff") or {}
        if isinstance(diff.get("before"), dict) and isinstance(diff.get("after"), dict):
            flip_records.append(
                {
                    "timestamp": row.get("timestamp"),
                    "before_snapshot": diff["before"],
                    "after_snapshot": diff["after"],
                }
            )
        else:
            flip_records.append(row)
    reverter = detect_active_reverter(flip_records, window_minutes=max(1, lookback // 60))
    reverter_blob = reverter.to_dict() if reverter else None

    sysmon_window = min(max(lookback, 10), 600)
    sysmon_events = collect_sysmon_proxy_events(sysmon_window, run=run)
    if recent:
        sysmon_events = filter_sysmon_within_seconds_of_transition(
            sysmon_events,
            str(recent[-1].get("timestamp") or ""),
            window_seconds=10,
        )
    procmon_events: list[Any] = []
    if procmon_csv:
        procmon_events = load_procmon_proxy_events(procmon_csv, since_seconds=lookback)

    attribution = compute_attribution_level(
        owner=owner,
        process_rows=process_rows,
        sysmon_events=sysmon_events,
        procmon_events=procmon_events,
        matched_port=int(localhost_port) if localhost_port else None,
        allowlist=allowlist,
    )

    chain_nodes = build_process_chain_nodes(
        focus_pid=int(owner["pid"]) if owner and owner.get("pid") is not None else None,
        process_rows=process_rows,
        matched_port=int(localhost_port) if localhost_port else None,
    )
    tree_json = render_process_tree_json(chain_nodes, matched_port=localhost_port)
    tree_text = render_process_tree_text(chain_nodes, matched_port=localhost_port)

    proxy = {
        "proxy_enable": reg.proxy_enable,
        "proxy_server": reg.proxy_server,
        "proxy_override": reg.proxy_override,
        "auto_config_url": reg.auto_config_url,
        "is_enabled": merged.get("is_enabled"),
        "proxy_mode": merged.get("proxy_mode"),
    }
    winhttp = {
        "raw": snap.winhttp_proxy,
        "direct_access": snap.winhttp_direct_access,
        "proxy_server_literal": snap.winhttp_proxy_server_literal,
        "error": None if snap.winhttp_direct_access is not None else "WinHTTP state unavailable",
    }
    correlation = build_correlation_result(parsed_dict=parsed_dict, owner=owner)
    correlation["attribution_level"] = attribution.level.value

    evidence = _build_evidence(
        proxy=proxy,
        parsed_dict=parsed_dict,
        attrib=attrib,
        owner=owner,
        winhttp=winhttp,
        attribution=attribution,
    )
    risk = classify_investigation_risk(
        proxy_enable=reg.proxy_enable,
        parsed=parsed_dict,
        port_owner=owner,
        before_snapshot=before_snapshot,
        registry_writer_proof=attribution.level.value == "PROVEN_REGISTRY_WRITER",
        allowlist_match=bool(allow_match.get("any_match")),
        attribution_level=attribution.level.value,
    )

    interpretation, next_steps = build_recovery_guidance(
        proxy_enable=reg.proxy_enable,
        is_localhost_proxy=bool(parsed_dict.get("is_localhost_proxy")),
        recent_transitions=list(recent),
        port_owner=owner,
        active_reverter=reverter_blob,
    )
    if risk.category == "REMEDIATION_NOT_STICKY" and reverter_blob is None:
        next_steps = (
            "Run scripts\\run_proxy_recovery_admin.ps1 (Administrator) for sticky re-enable.",
            *next_steps,
        )

    policy_recommendation = {
        "policy_decision": "PREVIEW",
        "recommended_policy_action": risk.recommended_policy_action,
        "posture_label": risk.posture_label,
        "rationale": risk.recommended_next_step,
        "no_auto_remediation": True,
    }

    evidence_table = tuple(item.to_jsonable() for item in attribution.evidence_items)

    all_limits = tuple(
        dict.fromkeys((*evidence.limitations, *risk.limitations, *attribution.limitations))
    )

    return ProxyInvestigationBundle(
        event_id=str(uuid.uuid4()),
        timestamp_utc=utc_now_iso(),
        tool_version=SCRIPT_VERSION,
        command="proxy-investigate",
        action_type="OBSERVE_ONLY",
        dry_run=True,
        policy_decision="PREVIEW",
        wininet=proxy,
        winhttp=winhttp,
        parsed_proxy=parsed_dict,
        port_owner=owner,
        correlation=correlation,
        evidence=evidence,
        risk=risk,
        recommended_next_steps=next_steps,
        limitations=all_limits,
        process_snapshot=process_snapshot,
        process_tree=tree_json,
        process_tree_text=tree_text,
        attribution=attribution.to_jsonable(),
        evidence_table=evidence_table,
        recent_transitions=recent,
        policy_recommendation=policy_recommendation,
        situation_interpretation=interpretation,
        active_reverter=reverter_blob,
    )


def format_investigation_human(bundle: ProxyInvestigationBundle) -> str:
    """Render operator-facing investigation summary."""

    mode_label = bundle.wininet.get("proxy_mode") or "unknown"
    if bundle.parsed_proxy.get("is_localhost_proxy"):
        mode_label = "manual localhost proxy"

    lines = [
        "Proxy Investigation Report",
        "",
        "=== Current proxy state ===",
        f"- ProxyEnable: {bundle.wininet.get('proxy_enable')}",
        f"- ProxyServer: {bundle.wininet.get('proxy_server') or '(empty)'}",
        f"- AutoConfigURL: {bundle.wininet.get('auto_config_url') or '(empty)'}",
        f"- ProxyOverride: {bundle.wininet.get('proxy_override') or '(empty)'}",
        f"- Parsed as: {mode_label}",
    ]
    host = bundle.parsed_proxy.get("localhost_host")
    port = bundle.parsed_proxy.get("localhost_port")
    if host:
        lines.append(f"- Localhost host: {host}")
    if port:
        lines.append(f"- Localhost port: {port}")

    lines.extend(["", "=== Situation ===", bundle.situation_interpretation])

    if bundle.active_reverter:
        ar = bundle.active_reverter
        lines.extend(
            [
                "",
                "=== Active reverter suspicion ===",
                f"- Class: {ar.get('incident_class')}",
                f"- ProxyEnable toggles in window: {ar.get('toggle_count')}",
                f"- Window: {ar.get('window_minutes')} minutes",
            ]
        )

    lines.extend(["", "=== Recent proxy transitions ==="])
    if bundle.recent_transitions:
        for row in bundle.recent_transitions[-5:]:
            diff = row.get("diff") or {}
            lines.append(f"- {row.get('timestamp')}: {summarize_transition_row(row)}")
            if diff.get("risk_level"):
                lines.append(f"  risk={diff.get('risk_level')} reason={diff.get('reason') or 'n/a'}")
    else:
        lines.append("- No proxy-watch transitions in look-back window (run proxy-watch to populate).")

    lines.extend(["", "=== Candidate processes ==="])
    owner = bundle.port_owner
    if owner:
        lines.extend(
            [
                f"- PID: {owner.get('pid')}",
                f"- Name: {owner.get('process_name') or 'unknown'}",
                f"- Parent: {owner.get('parent_name') or 'unknown'} (PID {owner.get('parent_pid') or 'unknown'})",
                f"- Path: {owner.get('executable_path') or 'unresolved_path'}",
                f"- Command line: {(owner.get('command_line') or '(unavailable)')[:120]}",
            ]
        )
    else:
        lines.append("- No listener owner resolved for configured port.")

    lines.extend(["", "=== Process tree ===", bundle.process_tree_text or "(empty)"])

    attr = bundle.attribution
    lines.extend(
        [
            "",
            "=== Attribution conclusion ===",
            f"- Level: {attr.get('level')}",
            f"- Suspect: {attr.get('suspect_process') or 'none'} (PID {attr.get('suspect_pid') or 'n/a'})",
            f"- Parent chain: {' -> '.join(attr.get('parent_chain') or []) or 'n/a'}",
            f"- Conclusion: {attr.get('conclusion_text')}",
        ]
    )

    lines.extend(["", "=== Evidence table ==="])
    for item in bundle.evidence_table:
        lines.append(
            f"- [{item.get('strength')}] {item.get('evidence_type')}: {item.get('description')}"
        )
    if not bundle.evidence_table:
        for tier in ("OBSERVED", "CORRELATED", "NOT_PROVEN"):
            tier_lines = [ln for ln in bundle.evidence.lines if ln.tier == tier]
            for line in tier_lines:
                lines.append(f"- ({tier}) {line.text}")

    lines.extend(
        [
            "",
            "=== Policy recommendation ===",
            f"- Decision: {bundle.policy_recommendation.get('policy_decision')} (no auto-remediation)",
            f"- Action: {bundle.policy_recommendation.get('recommended_policy_action')}",
            f"- Posture: {bundle.risk.posture_label}",
            f"- Risk level: {bundle.risk.risk_level} ({bundle.risk.category})",
        ]
    )

    lines.extend(["", "=== Limitations ==="])
    for lim in bundle.limitations:
        lines.append(f"- {lim}")

    lines.extend(["", "Recommended next steps:"])
    lines.append(f"- {bundle.risk.recommended_next_step}")
    for step in bundle.recommended_next_steps:
        lines.append(f"- {step}")

    lines.extend(["", f"Audit event ID (if --audit): {bundle.event_id}"])
    return "\n".join(lines)


def investigation_audit_row(bundle: ProxyInvestigationBundle) -> dict[str, Any]:
    """Build append-only audit row for ``logs/repair_audit.jsonl``."""

    payload = bundle.to_jsonable()
    return {
        "audit_event_id": bundle.event_id,
        "type": "repair",
        "subtype": "proxy_investigate",
        "event_kind": "investigation_read_only",
        "timestamp": bundle.timestamp_utc,
        "tool_version": bundle.tool_version,
        "command": bundle.command,
        "action_type": bundle.action_type,
        "dry_run": True,
        "policy_decision": bundle.policy_decision,
        "confirmation_token_used": None,
        "before_state": payload["wininet"],
        "after_state": payload["wininet"],
        "diff": {},
        "process_snapshot": bundle.process_snapshot,
        "attribution": payload.get("attribution"),
        "process_tree": payload.get("process_tree"),
        "evidence_table": payload.get("evidence_table"),
        "evidence": payload["evidence"],
        "risk": payload["risk"],
        "proof_status": payload.get("proof_status"),
        "correlation": payload.get("correlation"),
        "result": "success",
        "errors": [],
        "limitations": payload["limitations"],
        "investigation": payload,
    }
