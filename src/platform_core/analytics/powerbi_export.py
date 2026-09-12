"""Power BI-ready CSV export — normalize audit JSONL and case fixtures for PL-300 portfolio."""

from __future__ import annotations

import csv
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from src.platform_core.analytics.summary import (
    _classification_of,
    _evidence_tier_of,
    _incident_key,
    _load_audit_records,
    _policy_decision_of,
)
from src.platform_core.governance.chain_of_custody import verify_chain
from src.platform_core.governance.proof_tier import ProofTier

SCHEMA_VERSION = "powerbi_export.v1"

PROOF_TIERS = frozenset(t.value for t in ProofTier)
RISK_RATINGS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
POLICY_DECISIONS = frozenset({"ALLOW", "PREVIEW_ONLY", "BLOCK", "HUMAN_REVIEW"})
EXECUTION_AUTHORITIES = frozenset({"preview_only", "human_confirmed", "blocked"})
CONTROL_RESULTS = frozenset({"PASS", "FAIL", "PARTIAL", "NOT_TESTED"})

_INCIDENTS_COLUMNS = [
    "incident_id",
    "endpoint_id",
    "observed_at",
    "classification",
    "secondary_signals",
    "proof_tier",
    "risk_rating",
    "confidence_ordinal",
    "limitation_count",
    "policy_decision",
    "execution_authority",
    "human_review_required",
    "remediation_preview_generated",
    "hash_chain_valid",
    "ai_assisted_explanation",
    "audit_id",
]

_CONTROL_TESTS_COLUMNS = [
    "control_test_id",
    "incident_id",
    "endpoint_id",
    "observed_at",
    "control_id",
    "control_name",
    "classification",
    "control_test_result",
    "residual_risk",
    "remediation_owner",
    "review_frequency",
]

_AUDIT_EVENTS_COLUMNS = [
    "audit_event_id",
    "incident_id",
    "endpoint_id",
    "observed_at",
    "event_type",
    "classification",
    "policy_decision",
    "dry_run",
    "hash_chain_valid",
    "audit_id",
]

_REMEDIATION_PREVIEWS_COLUMNS = [
    "preview_id",
    "incident_id",
    "endpoint_id",
    "observed_at",
    "classification",
    "policy_decision",
    "execution_authority",
    "dry_run",
    "remediation_preview_generated",
    "human_review_required",
]

_RISK_DECISIONS_COLUMNS = [
    "risk_decision_id",
    "incident_id",
    "endpoint_id",
    "observed_at",
    "classification",
    "proof_tier",
    "risk_rating",
    "confidence_ordinal",
    "recommended_action",
    "execution_authority",
    "human_review_required",
    "evidence_hash",
    "audit_id",
]

_DATE_DIM_COLUMNS = [
    "date_key",
    "full_date",
    "year",
    "quarter",
    "month",
    "month_name",
    "week_of_year",
    "day_of_week",
    "day_name",
    "is_weekend",
    "fiscal_year",
    "fiscal_quarter",
]

_RISK_BY_CLASSIFICATION = {
    "DEAD_PROXY_CONFIG": "MEDIUM",
    "WININET_WINHTTP_MISMATCH": "MEDIUM",
    "LOCAL_PROXY_ACTIVE": "LOW",
    "UNKNOWN_LOCAL_PROXY": "HIGH",
    "PAC_CONFIGURED": "MEDIUM",
    "POSSIBLE_MITM_RISK": "HIGH",
    "REVERTER_SUSPECTED": "HIGH",
    "ERROR_INSUFFICIENT_DATA": "LOW",
    "NO_PROXY": "LOW",
    "UNCLASSIFIED": "MEDIUM",
}

_HUMAN_REVIEW_CLASSES = frozenset(
    {
        "UNKNOWN_LOCAL_PROXY",
        "POSSIBLE_MITM_RISK",
        "REVERTER_SUSPECTED",
        "SUSPICIOUS_PROXY",
    }
)


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _date_key(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    return int(dt.strftime("%Y%m%d"))


def _map_proof_tier(row: dict[str, Any]) -> str:
    tier = _nested_str(row, "proof_tier")
    if tier and tier in PROOF_TIERS:
        return tier
    legacy = (_evidence_tier_of(row) or "").lower()
    if legacy in ("proof", "behavioral_reproduction"):
        return ProofTier.T3_BEHAVIORAL_REPRODUCTION.value
    if legacy in ("correlation", "runtime_corroboration"):
        return ProofTier.T2_RUNTIME_CORROBORATION.value
    if legacy in ("observation", "config"):
        return ProofTier.T1_LOCAL_CONFIG_EVIDENCE.value
    if row.get("classification") or row.get("proxy_state"):
        return ProofTier.T1_LOCAL_CONFIG_EVIDENCE.value
    return ProofTier.T0_OBSERVATION_ONLY.value


def _nested_str(row: dict[str, Any], key: str) -> str | None:
    if row.get(key):
        return str(row[key])
    return None


def _normalize_policy(raw: str | None) -> str:
    if not raw:
        return "PREVIEW_ONLY"
    upper = raw.upper()
    if upper in ("BLOCK", "DENIED", "DENY", "BLOCKED"):
        return "BLOCK"
    if upper in ("ALLOW", "APPROVED"):
        return "ALLOW"
    if upper in ("REQUIRE_TYPED_CONFIRMATION", "REQUIRE_HUMAN_APPROVAL", "HUMAN_REVIEW"):
        return "HUMAN_REVIEW"
    return "PREVIEW_ONLY"


def _execution_authority(policy: str, dry_run: bool = True, executed: bool = False) -> str:
    if policy == "BLOCK":
        return "blocked"
    if executed and not dry_run and policy == "ALLOW":
        return "human_confirmed"
    return "preview_only"


def _risk_rating(classification: str | None) -> str:
    return _RISK_BY_CLASSIFICATION.get((classification or "").upper(), "MEDIUM")


def _confidence_ordinal(row: dict[str, Any]) -> int:
    block = row.get("classification")
    if isinstance(block, dict) and block.get("confidence") is not None:
        conf = float(block["confidence"])
        if conf >= 0.85:
            return 5
        if conf >= 0.65:
            return 4
        if conf >= 0.45:
            return 3
        if conf >= 0.25:
            return 2
        return 1
    tier = _map_proof_tier(row)
    mapping = {
        ProofTier.T0_OBSERVATION_ONLY.value: 1,
        ProofTier.T1_LOCAL_CONFIG_EVIDENCE.value: 2,
        ProofTier.T2_RUNTIME_CORROBORATION.value: 3,
        ProofTier.T3_BEHAVIORAL_REPRODUCTION.value: 4,
        ProofTier.T4_OPERATOR_CONFIRMED.value: 5,
    }
    return mapping.get(tier, 2)


def _limitation_count(row: dict[str, Any]) -> int:
    block = row.get("classification")
    if isinstance(block, dict):
        return len(block.get("limitations") or [])
    return len(row.get("limitations") or [])


def _secondary_signals(row: dict[str, Any]) -> str:
    block = row.get("classification")
    if isinstance(block, dict):
        signals = block.get("secondary_signals") or []
        return "|".join(str(s) for s in signals)
    return ""


def _endpoint_id(row: dict[str, Any], incident_id: str) -> str:
    return str(row.get("endpoint_id") or row.get("hostname") or f"EP-{incident_id[-3:]}")


def build_date_dim(*, start: date | None = None, end: date | None = None) -> list[dict[str, Any]]:
    """Build date dimension table (grain: one row per calendar day)."""
    start_d = start or date(2026, 6, 1)
    end_d = end or date(2026, 6, 30)
    rows: list[dict[str, Any]] = []
    current = start_d
    month_names = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    while current <= end_d:
        dt = datetime(current.year, current.month, current.day, tzinfo=UTC)
        fiscal_year = current.year if current.month >= 7 else current.year - 1
        fiscal_quarter = ((current.month - 7) % 12) // 3 + 1
        rows.append(
            {
                "date_key": int(current.strftime("%Y%m%d")),
                "full_date": current.isoformat(),
                "year": current.year,
                "quarter": (current.month - 1) // 3 + 1,
                "month": current.month,
                "month_name": month_names[current.month - 1],
                "week_of_year": int(dt.strftime("%V")),
                "day_of_week": current.isoweekday(),
                "day_name": day_names[current.weekday()],
                "is_weekend": current.weekday() >= 5,
                "fiscal_year": fiscal_year,
                "fiscal_quarter": fiscal_quarter,
            }
        )
        current += timedelta(days=1)
    return rows


def _incident_rows_from_audit(
    records: list[dict[str, Any]],
    *,
    hash_chain_valid: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_incident: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        by_incident[_incident_key(row)].append(row)

    incidents: list[dict[str, Any]] = []
    previews: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []
    risk_decisions: list[dict[str, Any]] = []

    for incident_id, rows in sorted(by_incident.items()):
        sorted_rows = sorted(rows, key=lambda r: str(r.get("timestamp") or ""))
        primary_row = next((r for r in sorted_rows if _classification_of(r)), sorted_rows[0])
        classification = _classification_of(primary_row) or "ERROR_INSUFFICIENT_DATA"
        observed = _parse_ts(primary_row.get("timestamp")) or datetime.now(UTC)
        policy_raw = _policy_decision_of(primary_row)
        policy = _normalize_policy(policy_raw)
        dry_run = bool(primary_row.get("dry_run", True))
        preview_generated = any(
            str(r.get("action", "")).lower() in ("remediation_preview", "preview") for r in rows
        )
        proof_tier = _map_proof_tier(primary_row)
        exec_auth = _execution_authority(policy, dry_run=dry_run)
        human_review = classification in _HUMAN_REVIEW_CLASSES or policy == "HUMAN_REVIEW"
        audit_id = str(primary_row.get("audit_id") or f"audit-{incident_id.lower()}")

        incidents.append(
            {
                "incident_id": incident_id,
                "endpoint_id": _endpoint_id(primary_row, incident_id),
                "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "classification": classification,
                "secondary_signals": _secondary_signals(primary_row),
                "proof_tier": proof_tier,
                "risk_rating": _risk_rating(classification),
                "confidence_ordinal": _confidence_ordinal(primary_row),
                "limitation_count": _limitation_count(primary_row),
                "policy_decision": policy,
                "execution_authority": exec_auth,
                "human_review_required": human_review,
                "remediation_preview_generated": preview_generated,
                "hash_chain_valid": hash_chain_valid,
                "ai_assisted_explanation": bool(primary_row.get("ai_assisted_explanation", False)),
                "audit_id": audit_id,
            }
        )

        risk_decisions.append(
            {
                "risk_decision_id": f"RD-{incident_id}",
                "incident_id": incident_id,
                "endpoint_id": _endpoint_id(primary_row, incident_id),
                "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "classification": classification,
                "proof_tier": proof_tier,
                "risk_rating": _risk_rating(classification),
                "confidence_ordinal": _confidence_ordinal(primary_row),
                "recommended_action": str(
                    (primary_row.get("policy_decision") or {}).get("action")
                    if isinstance(primary_row.get("policy_decision"), dict)
                    else primary_row.get("recommended_action")
                    or "Continue read-only investigation"
                ),
                "execution_authority": exec_auth,
                "human_review_required": human_review,
                "evidence_hash": str(primary_row.get("evidence_hash") or ""),
                "audit_id": audit_id,
            }
        )

        for idx, row in enumerate(sorted_rows, start=1):
            ts = _parse_ts(row.get("timestamp")) or observed
            cls = _classification_of(row) or classification
            pol = _normalize_policy(_policy_decision_of(row))
            audit_events.append(
                {
                    "audit_event_id": f"AUD-{incident_id}-{idx:03d}",
                    "incident_id": incident_id,
                    "endpoint_id": _endpoint_id(row, incident_id),
                    "observed_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "event_type": str(row.get("action") or row.get("command") or "observation"),
                    "classification": cls,
                    "policy_decision": pol,
                    "dry_run": bool(row.get("dry_run", True)),
                    "hash_chain_valid": hash_chain_valid,
                    "audit_id": audit_id,
                }
            )
            if str(row.get("action", "")).lower() in ("remediation_preview", "preview"):
                previews.append(
                    {
                        "preview_id": f"PREV-{incident_id}-{idx:03d}",
                        "incident_id": incident_id,
                        "endpoint_id": _endpoint_id(row, incident_id),
                        "observed_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "classification": cls,
                        "policy_decision": pol,
                        "execution_authority": _execution_authority(pol, dry_run=bool(row.get("dry_run", True))),
                        "dry_run": bool(row.get("dry_run", True)),
                        "remediation_preview_generated": True,
                        "human_review_required": human_review,
                    }
                )

    return incidents, audit_events, previews, risk_decisions


def _control_test_rows(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    catalog = [
        ("CTRL-EPR-001", "Dead WinINET proxy detection"),
        ("CTRL-EPR-002", "WinINET / WinHTTP stack alignment"),
        ("CTRL-EPR-003", "Local proxy listener governance"),
        ("CTRL-EPR-004", "PAC configuration review"),
        ("CTRL-EPR-005", "Unknown local proxy triage"),
        ("CTRL-EPR-006", "Proxy reverter monitoring"),
    ]
    rows: list[dict[str, Any]] = []
    for inc in incidents:
        cls = inc["classification"]
        for ctrl_id, ctrl_name in catalog:
            if ctrl_id == "CTRL-EPR-001" and cls == "DEAD_PROXY_CONFIG":
                result = "PASS"
            elif ctrl_id == "CTRL-EPR-002" and (
                cls == "WININET_WINHTTP_MISMATCH" or "WININET_WINHTTP_MISMATCH" in inc["secondary_signals"]
            ):
                result = "PASS"
            elif ctrl_id == "CTRL-EPR-003" and cls == "LOCAL_PROXY_ACTIVE":
                result = "PASS"
            elif ctrl_id == "CTRL-EPR-004" and cls == "PAC_CONFIGURED":
                result = "PASS"
            elif ctrl_id == "CTRL-EPR-005" and cls == "UNKNOWN_LOCAL_PROXY":
                result = "PASS"
            elif ctrl_id == "CTRL-EPR-006" and cls == "REVERTER_SUSPECTED":
                result = "PARTIAL"
            elif cls == "ERROR_INSUFFICIENT_DATA":
                result = "NOT_TESTED"
            else:
                result = "NOT_TESTED"
            rows.append(
                {
                    "control_test_id": f"CT-{inc['incident_id']}-{ctrl_id}",
                    "incident_id": inc["incident_id"],
                    "endpoint_id": inc["endpoint_id"],
                    "observed_at": inc["observed_at"],
                    "control_id": ctrl_id,
                    "control_name": ctrl_name,
                    "classification": cls,
                    "control_test_result": result,
                    "residual_risk": "Low" if result == "PASS" else "Medium",
                    "remediation_owner": "IT Operations",
                    "review_frequency": "Per incident",
                }
            )
    return rows


def portfolio_sample_tables() -> dict[str, list[dict[str, Any]]]:
    """Deterministic portfolio sample spanning all incident classes."""
    base = datetime(2026, 6, 10, 8, 0, 0, tzinfo=UTC)
    specs = [
        ("INC-101", "EP-FIN-001", "DEAD_PROXY_CONFIG", "WININET_WINHTTP_MISMATCH|DEAD_LOCALHOST_PORT", "T2_RUNTIME_CORROBORATION", "MEDIUM", 4, 2, "PREVIEW_ONLY", True, True),
        ("INC-102", "EP-FIN-002", "WININET_WINHTTP_MISMATCH", "LOCALHOST_PROXY", "T2_RUNTIME_CORROBORATION", "MEDIUM", 4, 2, "PREVIEW_ONLY", True, False),
        ("INC-103", "EP-DEV-001", "LOCAL_PROXY_ACTIVE", "LOCALHOST_PROXY", "T2_RUNTIME_CORROBORATION", "LOW", 3, 1, "PREVIEW_ONLY", False, False),
        ("INC-104", "EP-OPS-003", "UNKNOWN_LOCAL_PROXY", "SUSPICIOUS_LISTENER", "T1_LOCAL_CONFIG_EVIDENCE", "HIGH", 2, 3, "HUMAN_REVIEW", True, True),
        ("INC-105", "EP-GOV-001", "PAC_CONFIGURED", "PAC_URL_PRESENT", "T1_LOCAL_CONFIG_EVIDENCE", "MEDIUM", 3, 2, "HUMAN_REVIEW", True, False),
        ("INC-106", "EP-SEC-002", "POSSIBLE_MITM_RISK", "TLS_PATH_DIVERGENCE", "T2_RUNTIME_CORROBORATION", "HIGH", 3, 4, "PREVIEW_ONLY", True, True),
        ("INC-107", "EP-OPS-004", "REVERTER_SUSPECTED", "REPEATED_PROXY_REAPPEARANCE", "T1_LOCAL_CONFIG_EVIDENCE", "HIGH", 3, 3, "HUMAN_REVIEW", True, True),
        ("INC-108", "EP-HR-001", "ERROR_INSUFFICIENT_DATA", "", "T0_OBSERVATION_ONLY", "LOW", 1, 1, "BLOCK", False, False),
        ("INC-109", "EP-FIN-003", "DEAD_PROXY_CONFIG", "DEAD_LOCALHOST_PORT", "T1_LOCAL_CONFIG_EVIDENCE", "MEDIUM", 3, 2, "PREVIEW_ONLY", True, False),
        ("INC-110", "EP-DEV-002", "LOCAL_PROXY_ACTIVE", "KNOWN_DEV_TOOL", "T3_BEHAVIORAL_REPRODUCTION", "LOW", 4, 1, "ALLOW", False, False),
        ("INC-111", "EP-SEC-003", "POSSIBLE_MITM_RISK", "CERTIFICATE_MISMATCH", "T2_RUNTIME_CORROBORATION", "HIGH", 3, 4, "HUMAN_REVIEW", True, True),
        ("INC-112", "EP-GOV-002", "PAC_CONFIGURED", "PAC_MISROUTE", "T2_RUNTIME_CORROBORATION", "MEDIUM", 4, 2, "PREVIEW_ONLY", True, False),
    ]
    incidents: list[dict[str, Any]] = []
    risk_decisions: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []
    previews: list[dict[str, Any]] = []

    for idx, spec in enumerate(specs):
        (
            inc_id,
            ep_id,
            cls,
            secondary,
            proof_tier,
            risk,
            conf,
            lim_count,
            policy,
            preview_gen,
            ai_flag,
        ) = spec
        observed = base + timedelta(hours=idx * 6)
        exec_auth = _execution_authority(policy, dry_run=policy != "ALLOW")
        human = cls in _HUMAN_REVIEW_CLASSES or policy == "HUMAN_REVIEW"
        audit_id = f"audit-{inc_id.lower()}"
        incidents.append(
            {
                "incident_id": inc_id,
                "endpoint_id": ep_id,
                "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "classification": cls,
                "secondary_signals": secondary,
                "proof_tier": proof_tier,
                "risk_rating": risk,
                "confidence_ordinal": conf,
                "limitation_count": lim_count,
                "policy_decision": policy,
                "execution_authority": "human_confirmed" if policy == "ALLOW" else exec_auth,
                "human_review_required": human,
                "remediation_preview_generated": preview_gen,
                "hash_chain_valid": True,
                "ai_assisted_explanation": ai_flag,
                "audit_id": audit_id,
            }
        )
        risk_decisions.append(
            {
                "risk_decision_id": f"RD-{inc_id}",
                "incident_id": inc_id,
                "endpoint_id": ep_id,
                "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "classification": cls,
                "proof_tier": proof_tier,
                "risk_rating": risk,
                "confidence_ordinal": conf,
                "recommended_action": "Preview remediation" if preview_gen else "Collect additional evidence",
                "execution_authority": "human_confirmed" if policy == "ALLOW" else exec_auth,
                "human_review_required": human,
                "evidence_hash": f"sha256-sample-{inc_id.lower()}",
                "audit_id": audit_id,
            }
        )
        audit_events.append(
            {
                "audit_event_id": f"AUD-{inc_id}-001",
                "incident_id": inc_id,
                "endpoint_id": ep_id,
                "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "event_type": "classification_observed",
                "classification": cls,
                "policy_decision": policy,
                "dry_run": policy != "ALLOW",
                "hash_chain_valid": True,
                "audit_id": audit_id,
            }
        )
        if preview_gen:
            previews.append(
                {
                    "preview_id": f"PREV-{inc_id}-001",
                    "incident_id": inc_id,
                    "endpoint_id": ep_id,
                    "observed_at": (observed + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "classification": cls,
                    "policy_decision": policy,
                    "execution_authority": exec_auth,
                    "dry_run": True,
                    "remediation_preview_generated": True,
                    "human_review_required": human,
                }
            )

    control_tests = _control_test_rows(incidents)
    date_dim = build_date_dim(start=date(2026, 6, 1), end=date(2026, 6, 30))
    return {
        "incidents": incidents,
        "control_tests": control_tests,
        "audit_events": audit_events,
        "remediation_previews": previews,
        "risk_decisions": risk_decisions,
        "date_dim": date_dim,
    }


def export_powerbi_from_audit(
    audit_dir: Path,
    out_dir: Path,
    *,
    include_portfolio_seed: bool = False,
) -> dict[str, Any]:
    """Export normalized Power BI CSV tables from audit JSONL directory."""
    records, files, limitations = _load_audit_records(audit_dir)
    chain_ok = True
    if records:
        chain_ok, _ = verify_chain(records)

    if not records and not include_portfolio_seed:
        tables = portfolio_sample_tables()
        limitations.append("No audit records found; portfolio sample tables written for demonstration.")
    elif include_portfolio_seed or len(records) < 3:
        tables = portfolio_sample_tables()
        if records:
            inc, aud, prev, rd = _incident_rows_from_audit(records, hash_chain_valid=chain_ok)
            for key, extra in (
                ("incidents", inc),
                ("audit_events", aud),
                ("remediation_previews", prev),
                ("risk_decisions", rd),
            ):
                tables[key] = tables[key] + extra
            tables["control_tests"] = _control_test_rows(tables["incidents"])
    else:
        inc, aud, prev, rd = _incident_rows_from_audit(records, hash_chain_valid=chain_ok)
        tables = {
            "incidents": inc,
            "audit_events": aud,
            "remediation_previews": prev,
            "risk_decisions": rd,
            "control_tests": _control_test_rows(inc),
            "date_dim": build_date_dim(),
        }

    write_powerbi_csvs(tables, out_dir)
    return {
        "schema_version": SCHEMA_VERSION,
        "command": "analytics-export-powerbi",
        "audit_dir": str(audit_dir.resolve()),
        "files_written": list(tables.keys()),
        "record_counts": {k: len(v) for k, v in tables.items()},
        "hash_chain_valid": chain_ok,
        "limitations": limitations
        + [
            "CSV export is a snapshot — not a substitute for append-only JSONL custody.",
            "Classification is not accusation; AI assists explanation only.",
        ],
    }


def write_powerbi_csvs(tables: dict[str, list[dict[str, Any]]], out_dir: Path) -> None:
    """Write CSV files to out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "incidents.csv": (_INCIDENTS_COLUMNS, tables.get("incidents", [])),
        "control_tests.csv": (_CONTROL_TESTS_COLUMNS, tables.get("control_tests", [])),
        "audit_events.csv": (_AUDIT_EVENTS_COLUMNS, tables.get("audit_events", [])),
        "remediation_previews.csv": (_REMEDIATION_PREVIEWS_COLUMNS, tables.get("remediation_previews", [])),
        "risk_decisions.csv": (_RISK_DECISIONS_COLUMNS, tables.get("risk_decisions", [])),
        "date_dim.csv": (_DATE_DIM_COLUMNS, tables.get("date_dim", build_date_dim())),
    }
    for filename, (columns, rows) in mapping.items():
        path = out_dir / filename
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)


def write_portfolio_sample(out_dir: Path) -> dict[str, int]:
    """Write deterministic portfolio sample CSVs."""
    tables = portfolio_sample_tables()
    write_powerbi_csvs(tables, out_dir)
    return {k: len(v) for k, v in tables.items()}
