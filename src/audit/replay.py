"""Offline replay helpers for append-only ``logs/decision_runs.jsonl`` (`live_run_audit_v1`) rows.

Module responsibility:
    Scan JSONL artefacts, hydrate frozen ``LiveNetworkSnapshot`` payloads, rebuild proof structs, rerun deterministic
    scoring/policy passes, and format operator-readable parity summaries without spawning live probes.

Data handling / staleness:
    ``find_decision_run`` selects the newest matching JSON object for ``run_id`` when duplicates occur. Malformed
    lines skip quietly during iteration; callers should treat trailing partial lines like other JSONL tails.

Timezone:
    ``timestamp_utc`` strings remain opaque text for replay—they are echoed in reports rather than normalized here.

Verification guidance:
    Compare ``build_replay_report`` ``verification.*`` booleans versus manual diff of archival JSON snapshots when
    investigating scorer regressions rather than blaming hosts.

Boundary:
    Read-only recomputation plus stdout-oriented formatters—no persistence side effects besides optional caller logging.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal, cast

from ..core.models import LiveNetworkSnapshot, ParsedProxy, PortOwnerRecord, ProxyRegistrySnapshot
from ..diagnostics.features import FeatureVector
from ..hypothesis.live_scoring import score_live_snapshot
from ..observation.trust import assess_trust
from ..policy.hypothesis_gates import build_hypothesis_decisions
from ..proof.contracts import ProofObservation, ProofResult, ProofStatus

SchemaVersion = Literal["live_run_audit_v1"]

SCHEMA_VERSION: SchemaVersion = "live_run_audit_v1"
DECISION_RUNS_LOG = "logs/decision_runs.jsonl"


def _proxy_mode(raw: Any) -> Any:
    m = raw if isinstance(raw, str) else "missing"
    allowed = {
        "missing",
        "malformed",
        "disabled_server_field",
        "manual_localhost",
        "manual_explicit",
        "socks_localhost",
        "http_https_localhost",
        "multi_scheme_explicit",
    }
    return m if m in allowed else "missing"


def live_network_snapshot_from_observations(blob: dict[str, Any]) -> LiveNetworkSnapshot:
    """Hydrate frozen snapshot produced by :meth:`LiveNetworkSnapshot.to_dict`."""
    fv = FeatureVector.from_dict(blob["feature_vector"])
    ur = blob["user_proxy_registry"]
    reg = ProxyRegistrySnapshot(
        proxy_enable=ur.get("proxy_enable"),
        proxy_server=ur.get("proxy_server"),
        auto_config_url=ur.get("auto_config_url"),
        auto_detect=ur.get("auto_detect"),
        proxy_override=ur.get("proxy_override"),
    )
    ppd = blob["parsed_proxy_server"]
    parsed = ParsedProxy(
        raw=ppd.get("raw"),
        is_missing=bool(ppd.get("is_missing", False)),
        is_malformed=bool(ppd.get("is_malformed", False)),
        is_localhost_proxy=bool(ppd.get("is_localhost_proxy", False)),
        localhost_host=ppd.get("localhost_host"),
        localhost_port=ppd.get("localhost_port"),
        proxy_mode=cast(Any, _proxy_mode(ppd.get("proxy_mode"))),
        socks_port=ppd.get("socks_port"),
        http_localhost_port=ppd.get("http_localhost_port"),
        https_localhost_port=ppd.get("https_localhost_port"),
    )
    owners: list[PortOwnerRecord] = []
    for row in blob.get("port_attribution", {}).get("owners") or []:
        if not isinstance(row, dict) or "port" not in row:
            continue
        port = int(row["port"])
        owners.append(
            PortOwnerRecord(
                port=port,
                pid=row.get("pid"),
                process_name=row.get("process_name"),
                state=row.get("state"),
                local_address=row.get("local_address"),
                parent_pid=row.get("parent_pid"),
                parent_name=row.get("parent_name"),
                command_line=row.get("command_line"),
                executable_path=row.get("executable_path"),
                permission_limited=bool(row.get("permission_limited", False)),
            )
        )

    tcp_top: list[dict[str, Any]] = []
    for r in blob.get("tcp_top_ports_by_count") or []:
        if isinstance(r, dict):
            tcp_top.append(dict(r))

    interesting: list[dict[str, Any]] = []
    for r in blob.get("interesting_processes") or []:
        if isinstance(r, dict):
            interesting.append(dict(r))

    cmds: list[dict[str, str]] = []
    for r in blob.get("commands_executed") or []:
        if isinstance(r, dict):
            cmds.append({"label": str(r.get("label", "")), "cmd": str(r.get("cmd", ""))})

    return LiveNetworkSnapshot(
        generated_at_utc=str(blob.get("generated_at_utc") or ""),
        feature_vector=fv,
        proxy_registry=reg,
        parsed_proxy=parsed,
        port_owners=tuple(owners),
        localhost_listen_ports=tuple(int(x) for x in (blob.get("localhost_listen_ports") or []) if x is not None),
        interesting_processes=tuple(interesting),
        tcp_top_ports=tuple(tcp_top),
        commands_executed=tuple(cmds),
        permission_notes=tuple(str(x) for x in (blob.get("permission_notes") or []) if x is not None),
    )


def proof_result_from_stored(d: dict[str, Any] | None) -> ProofResult | None:
    """Hydrate :class:`ProofResult` from :meth:`ProofResult.to_dict` output."""
    if not d:
        return None
    observations: list[ProofObservation] = []
    for o in d.get("observations") or []:
        if not isinstance(o, dict):
            continue
        observations.append(
            ProofObservation(
                step_id=str(o.get("step_id") or ""),
                label=str(o.get("label") or ""),
                outcome=cast(Any, o.get("outcome") or "skipped"),
                detail=str(o.get("detail") or ""),
            )
        )
    st_raw = str(d.get("status") or "inconclusive")
    try:
        status = ProofStatus(st_raw)
    except ValueError:
        status = ProofStatus.INCONCLUSIVE
    return ProofResult(
        proof_id=str(d.get("proof_id") or ""),
        status=status,
        hypothesis=str(d.get("hypothesis") or ""),
        summary=str(d.get("summary") or ""),
        observations=tuple(observations),
        evidence=dict(d.get("evidence") or {}) if isinstance(d.get("evidence"), dict) else {},
    )


def iter_decision_runs_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Yield dict rows from a JSONL file (skips blank lines and decode errors)."""
    if not path.is_file():
        return
    yield from _iter_jsonl_lines(path)


def _iter_jsonl_lines(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield row


def find_decision_run(repo: Path, run_id: str) -> dict[str, Any] | None:
    """Return newest matching record (linear scan tail-friendly for small logs)."""
    path = repo / DECISION_RUNS_LOG
    last: dict[str, Any] | None = None
    for rec in iter_decision_runs_jsonl(path):
        if rec.get("schema_version") != SCHEMA_VERSION:
            continue
        rid = str(rec.get("run_id") or rec.get("diagnosis_id") or "")
        if rid == run_id:
            last = rec
    return last


def build_replay_report(record: dict[str, Any]) -> dict[str, Any]:
    """Re-score stored observations and diff against persisted hypotheses / decisions."""
    obs = record.get("observations")
    if not isinstance(obs, dict):
        return {"error": "record_missing_observations", "run_id": record.get("run_id")}

    snap = live_network_snapshot_from_observations(obs)
    ranked_new = score_live_snapshot(snap)
    stored_h = record.get("hypotheses_ranked") or []

    by_new = {s.hypothesis: float(s.confidence) for s in ranked_new}
    conf_mismatches: list[str] = []
    for row in stored_h:
        if not isinstance(row, dict):
            continue
        h = str(row.get("hypothesis") or "")
        if h in by_new and abs(by_new[h] - float(row.get("confidence") or 0.0)) > 1e-5:
            conf_mismatches.append(h)

    order_match = True
    for i, row in enumerate(stored_h):
        if not isinstance(row, dict):
            continue
        if i >= len(ranked_new):
            order_match = False
            break
        if str(row.get("hypothesis")) != str(ranked_new[i].hypothesis):
            order_match = False
            break

    proofs_requested = bool(record.get("proofs_requested", False))
    proof_err = record.get("proof_engine_error")
    proof_err_s = str(proof_err) if proof_err is not None else None
    raw_proof = record.get("proof_engine")
    localhost_blob = None
    if isinstance(raw_proof, dict):
        localhost_blob = raw_proof.get("localhost_proxy_https_contrast")
    if not isinstance(localhost_blob, dict):
        localhost_blob = None
    pr = proof_result_from_stored(localhost_blob)

    trust = assess_trust(
        snap,
        proof_result=pr,
        proofs_requested=proofs_requested,
        proof_engine_error=proof_err_s,
    )
    tuples = [(s.hypothesis, s.confidence, s.evidence) for s in ranked_new]
    decisions_new = build_hypothesis_decisions(
        ranked=tuples,
        localhost_proxy_proof=pr,
        proofs_enabled=proofs_requested,
        trust_assessment=trust,
    )
    stored_decisions = record.get("hypothesis_decisions") or []

    def row_sig(x: dict[str, Any]) -> tuple[Any, ...]:
        return (
            x.get("hypothesis"),
            x.get("confidence"),
            x.get("proof_status"),
            x.get("decision"),
            round(float(x.get("risk_score") or 0), 4),
        )

    dec_aligned = False
    if isinstance(stored_decisions, list) and len(decisions_new) == len(stored_decisions):
        dec_aligned = all(
            isinstance(s, dict) and row_sig(s) == row_sig(a) for s, a in zip(stored_decisions, decisions_new, strict=False)
        )

    verification = {
        "confidence_numeric_replay_match": len(conf_mismatches) == 0,
        "confidence_mismatched_hypotheses": conf_mismatches,
        "rank_order_match_primary_only": (
            stored_h and isinstance(stored_h[0], dict) and ranked_new and stored_h[0].get("hypothesis") == ranked_new[0].hypothesis
        ),
        "full_rank_order_match": order_match and len(stored_h) <= len(ranked_new),
        "decisions_core_fields_match": dec_aligned,
    }

    fv = snap.feature_vector
    steps = [
        f"[1.observe] run_id={record.get('run_id')} utc={record.get('timestamp_utc')}",
        f"[2.signals] ping_ip_ok={fv.ping_ip_ok} nslookup_ok={fv.nslookup_ok} tcp443_ok={fv.tcp_443_ok} browser_https_ok={fv.browser_http_ok}",
        "[3.rank] recomputed hypotheses from embedded observations only (no live subprocess).",
        f"[4.stored_primary] hypothesis={stored_h[0].get('hypothesis') if stored_h and isinstance(stored_h[0], dict) else 'n/a'} "
        f"confidence={stored_h[0].get('confidence') if stored_h and isinstance(stored_h[0], dict) else 'n/a'}",
        f"[5.replay_primary] hypothesis={ranked_new[0].hypothesis if ranked_new else 'n/a'} confidence={ranked_new[0].confidence if ranked_new else 'n/a'}",
        f"[6.proof_snapshot] proofs_requested={proofs_requested} proof_present={localhost_blob is not None}",
        f"[7.decision_primary_stored] {stored_decisions[0] if isinstance(stored_decisions, list) and stored_decisions else {}}",
        f"[8.decision_primary_replay] {decisions_new[0] if decisions_new else {}}",
        f"[9.verify] {json.dumps(verification, ensure_ascii=False)}",
        "[10.note] Proof contrast steps are archival (not re-invoked here); causal claim preserved in recorded proof blob.",
    ]

    return {
        "run_id": record.get("run_id"),
        "schema_version": record.get("schema_version"),
        "execution_flow_steps": steps,
        "verification": verification,
        "recomputed_hypotheses_preview": [
            {"hypothesis": s.hypothesis, "confidence": round(s.confidence, 6)} for s in ranked_new[:5]
        ],
    }


def format_replay_flow_text(report: dict[str, Any]) -> str:
    """Format :func:`build_replay_report` output for plaintext CLI."""
    lines = ["=== Replay execution flow (offline) ===", ""]
    if report.get("error"):
        lines.append(f"error: {report.get('error')}")
        return "\n".join(lines)
    lines.extend(str(s) for s in report.get("execution_flow_steps") or [])
    return "\n".join(lines)
