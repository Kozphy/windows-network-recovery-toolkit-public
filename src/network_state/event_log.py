"""Versioned reliability event model (schema 2.0) — append-only JSONL sinks under ``logs/``.

Complements legacy v1 repair audits without replacing them. Events track state, repairs,
verification, drift, attribution, and incident summaries for endpoint reliability workflows.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from ..core.jsonl import append_jsonl as _append_jsonl_core
from ..core.time_utils import utc_now_iso
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.remediation import INTERNET_SETTINGS_KEY

SCHEMA_VERSION = "2.0"

DEFAULT_TITLE = "Repeated WinINET localhost proxy re-enable"


def utc_now() -> str:
    """ISO-8601 UTC timestamp string (toolkit-standard)."""

    return utc_now_iso()


def new_event_id() -> str:
    """Unique id for ``event_id`` columns."""

    return str(uuid.uuid4())


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    """Append one JSON object (UTF-8, ``ensure_ascii=False``)."""

    _append_jsonl_core(path, row)


def logs_dir(repo_root: Path) -> Path:
    """Logs dir.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return repo_root / "logs"


def path_snapshots(repo_root: Path) -> Path:
    """Path snapshots.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return logs_dir(repo_root) / "snapshots.jsonl"


def path_repairs(repo_root: Path) -> Path:
    """Path repairs.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return logs_dir(repo_root) / "repairs.jsonl"


def path_verifications(repo_root: Path) -> Path:
    """Path verifications.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return logs_dir(repo_root) / "verifications.jsonl"


def path_drifts(repo_root: Path) -> Path:
    """Path drifts.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return logs_dir(repo_root) / "drifts.jsonl"


def path_attribution(repo_root: Path) -> Path:
    """Path attribution.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return logs_dir(repo_root) / "attribution.jsonl"


def path_incidents(repo_root: Path) -> Path:
    """Path incidents.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return logs_dir(repo_root) / "incidents.jsonl"


_INCIDENT_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "com.kozphy.wntr.incident")


def correlation_key(proxy_server: str | None) -> str:
    """Stable short key for clustering events (truncated SHA-256 of canonical proxy server string)."""

    raw = (proxy_server or "").strip().encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def incident_id_from_proxy(proxy_server: str | None) -> str:
    """Deterministic incident id derived from normalized ``ProxyServer`` string."""

    canon = (proxy_server or "").strip().lower()
    return str(uuid.uuid5(_INCIDENT_NS, canon))


def parse_proxy(observed: dict[str, Any]) -> dict[str, Any]:
    """Build the v2 ``parsed`` block from ``observed`` (``ProxyEnable`` + ``ProxyServer``)."""

    pe = observed.get("ProxyEnable")
    ps = observed.get("ProxyServer")
    ps_str = ps if isinstance(ps, str) or ps is None else str(ps)

    parsed = parse_proxy_server(ps_str if isinstance(ps_str, str) else None)
    is_enabled = pe == 1
    mode = parsed.proxy_mode
    # Treat disabled enable flag as informational even if ProxyServer parses as localhost.
    if not is_enabled and mode != "missing":
        pass
    out: dict[str, Any] = {
        "is_enabled": is_enabled,
        "proxy_mode": mode,
        "localhost_host": parsed.localhost_host,
        "localhost_port": parsed.localhost_port,
        "is_localhost_proxy": parsed.is_localhost_proxy,
    }
    return out


def _base_row(event_type: str, *, incident_id: str, correlation_key_val: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "event_type": event_type,
        "event_id": new_event_id(),
        "timestamp_utc": utc_now(),
        "incident_id": incident_id,
        "correlation_key": correlation_key_val,
    }


def log_snapshot(
    repo_root: Path,
    *,
    observed: dict[str, Any],
    incident_id: str | None = None,
    correlation_key_val: str | None = None,
    scope: str = "HKCU",
    source: str = "wininet_registry",
) -> str:
    """Append ``snapshot`` event; returns ``event_id``."""

    ps = observed.get("ProxyServer")
    ps_s = ps if isinstance(ps, str) else (str(ps) if ps is not None else "")
    corr = correlation_key_val or correlation_key(ps_s if ps_s else None)
    inc = incident_id or incident_id_from_proxy(ps_s if ps_s else None)

    normalized_observed = {
        "ProxyEnable": observed.get("ProxyEnable"),
        "ProxyServer": observed.get("ProxyServer"),
        "AutoConfigURL": observed.get("AutoConfigURL"),
        "AutoDetect": observed.get("AutoDetect"),
        "ProxyOverride": observed.get("ProxyOverride"),
    }
    row = _base_row("snapshot", incident_id=inc, correlation_key_val=corr)
    row.update(
        {
            "scope": scope,
            "source": source,
            "observed": normalized_observed,
            "parsed": parse_proxy(normalized_observed),
        }
    )
    append_jsonl(path_snapshots(repo_root), row)
    return str(row["event_id"])


def _target_for_argv(argv: list[str]) -> dict[str, Any]:
    """Derive coarse ``target`` metadata from ``reg.exe`` argv (best-effort)."""

    argv_l = list(argv)
    key = INTERNET_SETTINGS_KEY
    target: dict[str, Any] = {"registry_path": key}
    if "delete" in argv_l:
        try:
            vi = argv_l.index("/v") + 1
            target["value_name"] = argv_l[vi]
            target["operation"] = "delete"
        except (IndexError, ValueError):
            target["operation"] = "delete"
        return target
    if "/v" in argv_l:
        try:
            vi = argv_l.index("/v") + 1
            target["value_name"] = argv_l[vi]
            if "/d" in argv_l:
                di = argv_l.index("/d") + 1
                raw = argv_l[di]
                if raw.startswith("0x"):
                    target["desired_value"] = int(raw, 16)
                else:
                    target["desired_value"] = int(raw)
        except (IndexError, ValueError):
            pass
    return target


def log_repair_attempt(
    repo_root: Path,
    *,
    snapshot_event_id: str,
    incident_id: str,
    correlation_key_val: str,
    mutation_argv: list[str],
    result: dict[str, Any],
    action_type: str = "disable_wininet_hkcu_proxy",
    confirmation_required: bool = True,
    confirmation_method: str = "typed_phrase",
    risk: dict[str, Any] | None = None,
) -> str:
    """Append ``repair_attempt`` event; returns ``event_id``."""

    row = _base_row(
        "repair_attempt", incident_id=incident_id, correlation_key_val=correlation_key_val
    )
    default_risk: dict[str, Any] = {
        "risk_level": "low",
        "changes_winhttp": False,
        "changes_system_proxy": False,
        "changes_hkcu_only": True,
    }
    row.update(
        {
            "snapshot_event_id": snapshot_event_id,
            "action_type": action_type,
            "target": _target_for_argv(mutation_argv),
            "mutation_argv": list(mutation_argv),
            "result": result,
            "confirmation": {"required": confirmation_required, "method": confirmation_method},
            "risk": risk or default_risk,
        }
    )
    append_jsonl(path_repairs(repo_root), row)
    return str(row["event_id"])


def log_verification(
    repo_root: Path,
    *,
    repair_event_id: str,
    incident_id: str,
    correlation_key_val: str,
    expected: dict[str, Any],
    observed: dict[str, Any],
    ok: bool,
    interpretation: str | None = None,
    confidence: float | None = None,
) -> str:
    """Append ``verification`` event."""

    interp = interpretation
    if interp is None:
        interp = (
            "ProxyEnable matches expected disabled value."
            if ok
            else "Observed ProxyEnable differs from expectation."
        )
    conf = confidence
    if conf is None:
        conf = 0.99 if ok else 0.5

    row = _base_row(
        "verification", incident_id=incident_id, correlation_key_val=correlation_key_val
    )
    row.update(
        {
            "repair_event_id": repair_event_id,
            "expected": dict(expected),
            "observed": dict(observed),
            "ok": ok,
            "confidence": float(conf),
            "interpretation": interp,
        }
    )
    append_jsonl(path_verifications(repo_root), row)
    return str(row["event_id"])


def drift_severity(repeat_count: int) -> str:
    """``high`` if ``repeat_count >= 3``, else ``medium``."""

    return "high" if repeat_count >= 3 else "medium"


def count_drift_events(
    repo_root: Path, correlation_key_val: str, drift_type: str = "proxy_reenabled"
) -> int:
    """Count existing v2 drift rows for repeat indexing."""

    p = path_drifts(repo_root)
    if not p.is_file():
        return 0
    n = 0
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if o.get("schema_version") != SCHEMA_VERSION:
                continue
            if o.get("correlation_key") != correlation_key_val:
                continue
            if o.get("event_type") != "drift_detected":
                continue
            if o.get("drift_type") == drift_type:
                n += 1
    except OSError:
        return 0
    return n


def log_drift(
    repo_root: Path,
    *,
    drift_type: str,
    incident_id: str,
    correlation_key_val: str,
    previous_known_good: dict[str, Any],
    current: dict[str, Any],
    repeat_count: int | None = None,
    severity: str | None = None,
    interpretation: str | None = None,
    confidence: float = 0.95,
) -> str:
    """Append ``drift_detected``. When ``repeat_count`` omitted, derives from ``drifts.jsonl``."""

    rc = repeat_count
    if rc is None:
        rc = count_drift_events(repo_root, correlation_key_val, drift_type) + 1
    sev = severity or drift_severity(rc)
    interp = interpretation
    if interp is None:
        interp = (
            "WinINET proxy was re-enabled after prior baseline. "
            "Repair may be temporary; root cause likely external process, policy, startup item, or agent."
        )

    row = _base_row(
        "drift_detected", incident_id=incident_id, correlation_key_val=correlation_key_val
    )
    row.update(
        {
            "drift_type": drift_type,
            "previous_known_good": dict(previous_known_good),
            "current": dict(current),
            "repeat_count": rc,
            "severity": sev,
            "confidence": float(confidence),
            "interpretation": interp,
        }
    )
    append_jsonl(path_drifts(repo_root), row)
    return str(row["event_id"])


def log_attribution(
    repo_root: Path,
    *,
    incident_id: str,
    correlation_key_val: str,
    target: dict[str, Any],
    evidence: dict[str, Any],
    hypothesis: str,
    confidence: float,
    limits: list[str],
) -> str:
    """Append ``attribution`` (operators must respect ``limits``; no malware claims)."""

    row = _base_row("attribution", incident_id=incident_id, correlation_key_val=correlation_key_val)
    row.update(
        {
            "target": dict(target),
            "evidence": dict(evidence),
            "hypothesis": hypothesis,
            "confidence": float(confidence),
            "limits": list(limits),
        }
    )
    append_jsonl(path_attribution(repo_root), row)
    return str(row["event_id"])


def _tail_incident_summary(repo_root: Path, incident_id: str) -> dict[str, Any] | None:
    p = path_incidents(repo_root)
    if not p.is_file():
        return None
    last: dict[str, Any] | None = None
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if o.get("event_type") == "incident_summary" and o.get("incident_id") == incident_id:
                last = o
    except OSError:
        return None
    return last


def update_or_write_incident_summary(
    repo_root: Path,
    *,
    incident_id: str,
    correlation_key_val: str,
    symptom: dict[str, Any],
    counters_patch: dict[str, Any],
    assessment: dict[str, Any],
    recommended_next_actions: list[str],
    title: str = DEFAULT_TITLE,
    status: str = "open",
) -> None:
    """Append a new ``incident_summary`` row (prior summary merged when present).

    ``counters_patch`` merges into prior ``counters`` (integer fields add;
    ``unique_ports`` union). ``first_seen_utc`` preserved from prior row when present.
    """

    prev = _tail_incident_summary(repo_root, incident_id)
    now_ts = utc_now()
    base_counters: dict[str, Any] = {
        "repair_attempts": 0,
        "successful_repairs": 0,
        "drift_events": 0,
        "unique_ports": [],
    }
    first_seen = now_ts
    if prev:
        base_counters.update(prev.get("counters") or {})
        first_seen = str(prev.get("first_seen_utc") or prev.get("timestamp_utc") or now_ts)

    merged: dict[str, Any] = dict(base_counters)
    patch = dict(counters_patch or {})
    for k in ("repair_attempts", "successful_repairs", "drift_events"):
        if k in patch:
            merged[k] = int(merged.get(k) or 0) + int(patch[k])
            del patch[k]
    up = patch.pop("unique_ports", None)
    if isinstance(up, list):
        ports: set[int] = set()
        for x in merged.get("unique_ports") or []:
            try:
                ports.add(int(x))
            except (TypeError, ValueError):
                continue
        for p in up:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                continue
        merged["unique_ports"] = sorted(ports)
    for k, v in patch.items():
        merged[k] = v

    merged_symptom = dict(prev.get("symptom") or {}) if prev else {}
    merged_symptom.update(symptom)

    row: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_type": "incident_summary",
        "event_id": new_event_id(),
        "timestamp_utc": now_ts,
        "incident_id": incident_id,
        "correlation_key": correlation_key_val,
        "title": title,
        "status": status,
        "first_seen_utc": first_seen,
        "last_seen_utc": now_ts,
        "symptom": merged_symptom,
        "counters": merged,
        "assessment": dict(assessment),
        "recommended_next_actions": list(recommended_next_actions),
    }
    append_jsonl(path_incidents(repo_root), row)
