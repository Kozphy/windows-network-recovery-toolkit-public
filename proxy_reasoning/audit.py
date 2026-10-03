"""Append-only JSONL audit and replay for proxy reasoning runs.

Module responsibility:
    Serialize ``ProxyReasoningRun`` rows, append to ``logs/proxy_reasoning_audit.jsonl``,
    iterate records, and replay decisions without re-probing.

Side effects:
    ``append_proxy_reasoning_run`` creates ``logs/`` parents and appends one JSON line.

Idempotency:
    Append is not idempotent; replay reads historical lines only.

Audit Notes:
    * ``proof_hints`` field mirrors entity evidence attributes for reviewers — validate against raw signals.
    * Corrupt JSONL lines are skipped by iterators; tail gaps imply manual log repair.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from proxy_reasoning.constants import DEFAULT_AUDIT_FILE
from proxy_reasoning.models import ProxyReasoningRun, ProxySignal
from proxy_reasoning.pipeline import run_proxy_reasoning


def default_audit_path() -> Path:
    """Default local audit path under logs/."""
    return Path(DEFAULT_AUDIT_FILE)


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def to_audit_record(run: ProxyReasoningRun) -> dict[str, Any]:
    """Serialize a run for append-only storage and replay."""
    return {
        "record_type": "proxy_reasoning_run",
        "run_id": run.run_id,
        "timestamp": run.timestamp,
        "schema_version": run.schema_version,
        "engine_version": run.engine_version,
        "signals": [s.model_dump(mode="json") for s in run.signals],
        "events": [e.model_dump(mode="json") for e in run.events],
        "hypotheses": [h.model_dump(mode="json") for h in run.hypotheses],
        "evidence_tree": run.evidence_tree,
        "verification_results": [v.model_dump(mode="json") for v in run.verification_results],
        "confidence_boundary": run.confidence_boundary.model_dump(mode="json"),
        "policy_decision": run.policy_decision.model_dump(mode="json"),
        "entity": run.entity.model_dump(mode="json"),
        "limitations": run.limitations,
        "user_visible_summary": run.user_visible_summary,
        "requested_action": run.requested_action,
        "proof_hints": run.entity.evidence_attributes.model_dump(mode="json"),
    }


def append_proxy_reasoning_run(run: ProxyReasoningRun, *, path: Path | None = None) -> Path:
    """Append one reasoning run to JSONL."""
    out = path or default_audit_path()
    _append_jsonl(out, to_audit_record(run))
    return out


def iter_proxy_reasoning_records(path: Path | None = None) -> Iterator[dict[str, Any]]:
    """Yield audit records from JSONL."""
    import json

    target = path or default_audit_path()
    if not target.exists():
        return
    with target.open(encoding="utf-8") as handle:
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


def replay_proxy_reasoning_record(record: dict[str, Any]) -> ProxyReasoningRun:
    """Reconstruct policy/hypothesis decision from stored signals — no re-probing."""
    signals_blob = record.get("signals") or []
    signals = [ProxySignal(**item) for item in signals_blob if isinstance(item, dict)]
    proof_hints = record.get("proof_hints") if isinstance(record.get("proof_hints"), dict) else {}
    # Rebuild payload-like dict from signals for entity reconstruction
    payload = {s.name: s.value for s in signals}
    if isinstance(record.get("entity"), dict):
        ent = record["entity"]
        payload.update(
            {
                "proxy_enable": (ent.get("configuration_attributes") or {}).get("proxy_enable"),
                "proxy_server": (ent.get("configuration_attributes") or {}).get("proxy_server"),
                "process_name": (ent.get("process_attribution_attributes") or {}).get(
                    "process_name"
                ),
                "suspicious_cert_observed": False,
            },
        )
    return run_proxy_reasoning(
        payload=payload,
        requested_action=record.get("requested_action"),
        proof_hints=proof_hints if proof_hints else None,
        run_id=str(record.get("run_id") or ""),
    )
