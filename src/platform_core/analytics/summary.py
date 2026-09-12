"""Summarize audit JSONL directories into portfolio KPI outputs."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.governance.chain_of_custody import verify_chain
from src.platform_core.governance.evidence_to_action import attach_governance_envelope

SCHEMA_VERSION = "analytics_summary.v1"
_BLOCKED_ACTIONS = frozenset(
    {"KILL_PROXY_PROCESS", "FIREWALL_RESET", "ADAPTER_DISABLE", "WINHTTP_MODIFY"}
)
_DEFAULT_LIMITATIONS = [
    "Observation is not proof; correlation is not causation.",
    "Dry-run is default for all state-changing commands.",
]
_PROXY_PORT_RE = re.compile(r":(\d{2,5})\b")
_INCIDENT_KEYS = ("incident_id", "case_id", "target_id", "audit_id")


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_jsonl_file(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    limitations: list[str] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as exc:
            limitations.append(f"Skipped malformed JSON in {path.name}:{line_no} ({exc.msg}).")
            continue
        if isinstance(row, dict):
            records.append(row)
        else:
            limitations.append(f"Skipped non-object JSON in {path.name}:{line_no}.")
    return records, limitations


def _load_audit_records(audit_dir: Path) -> tuple[list[dict[str, Any]], list[Path], list[str]]:
    limitations: list[str] = []
    if not audit_dir.is_dir():
        return [], [], [f"Audit directory not found: {audit_dir}"]

    files = sorted(audit_dir.glob("*.jsonl"))
    if not files:
        return [], [], [f"No *.jsonl audit files found in {audit_dir}."]

    all_records: list[dict[str, Any]] = []
    for path in files:
        rows, file_limits = _parse_jsonl_file(path)
        all_records.extend(rows)
        limitations.extend(file_limits)
    return all_records, files, limitations


def _nested_get(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    for container_key in ("classification", "policy_decision", "proof", "proof_status"):
        container = row.get(container_key)
        if isinstance(container, dict):
            for key in keys:
                if key in container and container[key] not in (None, ""):
                    return container[key]
    return None


def _classification_of(row: dict[str, Any]) -> str | None:
    value = _nested_get(
        row,
        "primary_classification",
        "classification",
        "incident_type",
        "category",
    )
    if value is None:
        return None
    if isinstance(value, dict):
        return str(value.get("primary_classification") or value.get("name") or "")
    return str(value)


def _evidence_tier_of(row: dict[str, Any]) -> str | None:
    value = _nested_get(row, "evidence_tier", "evidence_level", "claim_strength")
    if value is None:
        proof = row.get("proof") or row.get("proof_status")
        if isinstance(proof, dict):
            status = (proof.get("conclusion") or {}).get("status") if isinstance(proof.get("conclusion"), dict) else proof.get("conclusion_status")
            if status == "supported":
                return "proof"
            if status in ("weakened", "inconclusive"):
                return "correlation"
        return None
    return str(value).lower().replace("observed_only", "observation")


def _policy_decision_of(row: dict[str, Any]) -> str | None:
    value = _nested_get(row, "outcome", "decision", "policy_decision", "policy_outcome")
    if value is None:
        return None
    return str(value).upper()


def _incident_key(row: dict[str, Any]) -> str:
    for key in _INCIDENT_KEYS:
        if row.get(key):
            return str(row[key])
    if row.get("timestamp"):
        return f"ts:{row['timestamp']}"
    return json.dumps(row, sort_keys=True, default=str)[:80]


def _extract_proxy_port(row: dict[str, Any]) -> str | None:
    candidates: list[str] = []
    for key in ("proxy_server", "wininet_proxy_server", "observed_value"):
        val = row.get(key)
        if isinstance(val, str):
            candidates.append(val)
    state = row.get("proxy_state")
    if isinstance(state, dict) and state.get("wininet_proxy_server"):
        candidates.append(str(state["wininet_proxy_server"]))
    if isinstance(state, dict) and state.get("localhost_port"):
        candidates.append(f":{state['localhost_port']}")
    owner = row.get("proxy_owner")
    if isinstance(owner, dict) and owner.get("localhost_port"):
        candidates.append(f":{owner['localhost_port']}")
    for text in candidates:
        match = _PROXY_PORT_RE.search(text)
        if match:
            return match.group(1)
    return None


def _is_remediation_preview(row: dict[str, Any]) -> bool:
    action = str(row.get("action") or row.get("proposed_action") or "").lower()
    if "preview" in action:
        return True
    if row.get("dry_run") is True and action:
        return True
    if _nested_get(row, "outcome") == "PREVIEW_ONLY":
        return True
    return False


def _is_destructive_blocked(row: dict[str, Any]) -> bool:
    action = str(row.get("action") or row.get("blocked_action") or row.get("proposed_action") or "").upper()
    decision = str(row.get("decision") or _nested_get(row, "outcome") or "").lower()
    if decision == "blocked":
        return True
    if action in _BLOCKED_ACTIONS:
        return True
    if any(token in action for token in ("KILL_", "FIREWALL_", "ADAPTER_", "WINHTTP_")):
        return decision in ("blocked", "deny", "denied")
    return False


def _verify_audit_files(files: list[Path]) -> dict[str, Any]:
    per_file: list[dict[str, Any]] = []
    for path in files:
        records, _ = _parse_jsonl_file(path)
        if not records:
            per_file.append({"file": path.name, "verified": None, "message": "empty", "records": 0})
            continue
        if "current_hash" in records[0]:
            ok, msg = verify_chain(records)
            per_file.append({"file": path.name, "verified": ok, "message": msg, "records": len(records)})
        else:
            per_file.append({
                "file": path.name,
                "verified": None,
                "message": "no hash chain fields",
                "records": len(records),
            })
    verified_count = sum(1 for item in per_file if item["verified"] is True)
    failed_count = sum(1 for item in per_file if item["verified"] is False)
    return {
        "files_checked": len(per_file),
        "hash_chain_valid_count": verified_count,
        "hash_chain_invalid_count": failed_count,
        "hash_chain_not_applicable_count": sum(1 for item in per_file if item["verified"] is None),
        "per_file": per_file,
    }


def build_analytics_summary(
    audit_dir: Path,
    *,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Build analytics summary.

    Args:
        audit_dir: audit dir supplied by the caller.
        source_label: source label supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.
    """
    records, files, load_limits = _load_audit_records(audit_dir)
    limitations = list(_DEFAULT_LIMITATIONS)
    limitations.extend(load_limits)

    incident_keys = {_incident_key(row) for row in records}
    classifications = Counter(filter(None, (_classification_of(row) for row in records)))
    if not classifications and records:
        classifications = Counter({"UNCLASSIFIED": len(incident_keys)})

    evidence_tiers = Counter(filter(None, (_evidence_tier_of(row) for row in records)))
    policy_decisions = Counter(filter(None, (_policy_decision_of(row) for row in records)))
    proxy_ports = Counter(filter(None, (_extract_proxy_port(row) for row in records)))

    remediation_preview_count = sum(1 for row in records if _is_remediation_preview(row))
    destructive_blocked_count = sum(1 for row in records if _is_destructive_blocked(row))

    audit_integrity = _verify_audit_files(files) if files else {
        "files_checked": 0,
        "hash_chain_valid_count": 0,
        "hash_chain_invalid_count": 0,
        "hash_chain_not_applicable_count": 0,
        "per_file": [],
    }

    if not records:
        limitations.append("No audit records available; counts are zero.")
        limitations.append("Confidence scores are ordinal, not statistical probabilities.")

    summary = {
        "total_incident_count": len(incident_keys) if incident_keys else len(records),
        "total_audit_records": len(records),
        "audit_files_scanned": len(files),
    }

    counts = {
        "incidents_by_classification": dict(classifications),
        "evidence_tier_distribution": dict(evidence_tiers),
        "policy_decision_distribution": dict(policy_decisions),
        "remediation_preview_count": remediation_preview_count,
        "destructive_action_blocked_count": destructive_blocked_count,
        "top_recurring_proxy_ports": [
            {"port": port, "count": count} for port, count in proxy_ports.most_common(10)
        ],
    }

    payload = {
        "schema_version": SCHEMA_VERSION,
        "summary": summary,
        "counts": counts,
        "audit_integrity": audit_integrity,
        "limitations": limitations,
        "source": {
            "audit_dir": str(audit_dir.resolve()),
            "label": source_label or audit_dir.name,
            "files": [path.name for path in files],
        },
        "generated_at": _now_iso(),
    }
    dominant_tier = None
    if evidence_tiers:
        dominant_tier = evidence_tiers.most_common(1)[0][0]
    dominant_policy = policy_decisions.most_common(1)[0][0] if policy_decisions else "PREVIEW_ONLY"
    return attach_governance_envelope(
        payload,
        evidence_tier=dominant_tier,
        policy_outcome=dominant_policy,
        dry_run=True,
        requires_confirmation=True,
        limitations=["Aggregate analytics — classifications are not accusations."],
    )


def format_analytics_markdown(payload: dict[str, Any]) -> str:
    """Format analytics markdown.

    Args:
        payload: payload supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.
    """
    summary = payload.get("summary") or {}
    counts = payload.get("counts") or {}
    integrity = payload.get("audit_integrity") or {}
    limitations = payload.get("limitations") or []

    lines = [
        "# Endpoint Risk Analytics Summary",
        "",
        "## Executive Summary",
        "",
        (
            f"Scanned **{summary.get('audit_files_scanned', 0)}** audit file(s) "
            f"with **{summary.get('total_audit_records', 0)}** record(s) "
            f"covering **{summary.get('total_incident_count', 0)}** incident key(s)."
        ),
        "",
        "This summary supports technology risk and audit analytics. "
        "It is not antivirus, EDR, or autonomous remediation output.",
        "",
        "## KPI Summary",
        "",
        f"- Total incidents (unique keys): **{summary.get('total_incident_count', 0)}**",
        f"- Remediation previews: **{counts.get('remediation_preview_count', 0)}**",
        f"- Destructive actions blocked: **{counts.get('destructive_action_blocked_count', 0)}**",
        f"- Audit files with valid hash chain: **{integrity.get('hash_chain_valid_count', 0)}**",
        "",
        "## Classification Distribution",
        "",
    ]
    by_class = counts.get("incidents_by_classification") or {}
    if by_class:
        for name, value in sorted(by_class.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- **{name}**: {value}")
    else:
        lines.append("- _No classification data in audit records._")

    lines.extend(["", "## Evidence Tier Distribution", ""])
    tiers = counts.get("evidence_tier_distribution") or {}
    if tiers:
        for name, value in sorted(tiers.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- **{name}**: {value}")
    else:
        lines.append("- _No evidence tier fields found._")

    lines.extend(["", "## Policy Decision Distribution", ""])
    policies = counts.get("policy_decision_distribution") or {}
    if policies:
        for name, value in sorted(policies.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- **{name}**: {value}")
    else:
        lines.append("- _No policy decision fields found._")

    lines.extend(["", "## Remediation Preview Summary", ""])
    lines.append(f"- Preview events: **{counts.get('remediation_preview_count', 0)}**")
    lines.append(f"- Blocked destructive actions: **{counts.get('destructive_action_blocked_count', 0)}**")

    lines.extend(["", "## Audit Integrity", ""])
    lines.append(f"- Files checked: **{integrity.get('files_checked', 0)}**")
    lines.append(f"- Hash chain valid: **{integrity.get('hash_chain_valid_count', 0)}**")
    lines.append(f"- Hash chain invalid: **{integrity.get('hash_chain_invalid_count', 0)}**")
    lines.append(f"- Hash chain N/A: **{integrity.get('hash_chain_not_applicable_count', 0)}**")

    ports = counts.get("top_recurring_proxy_ports") or []
    if ports:
        lines.extend(["", "## Top Recurring Proxy Ports", ""])
        for item in ports:
            lines.append(f"- Port **{item['port']}**: {item['count']} occurrence(s)")

    lines.extend(["", "## Limitations", ""])
    for item in limitations:
        lines.append(f"- {item}")

    lines.extend(["", f"_Generated at {payload.get('generated_at', '')}_"])
    return "\n".join(lines)
