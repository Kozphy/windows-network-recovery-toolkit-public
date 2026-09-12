"""Append-only audit and deterministic replay helpers for reasoning runs.

Module responsibility:
    Serialize :class:`~platform_core.reasoning_models.ReasoningRun` rows to JSONL and
    recompute decisions offline via :func:`replay_reasoning_record` without host probes.

System placement:
    Consumed by platform demos, tests, and ``python -m src replay`` bridges; stores
    under ``platform_data/reasoning_runs.jsonl`` by default.

Key invariants:
    * Replay uses stored observations + proof blob only — no live subprocess probes.
    * ``explicit_confirmation`` is inferred from canonical reason codes in the audit row.

Output guarantees:
    Each append is one JSON object per line; malformed lines skipped by readers in
    :mod:`platform_core.storage`.

Idempotency:
    Appends are append-only; replay does not mutate the audit file.

Failure modes:
    Missing or partial audit rows may raise on ``Observation`` / ``ProofResult`` parse;
    callers should validate schema before replay in production tooling.

Audit Notes:
    Compare replay output to original ``policy_decision`` when investigating policy
    regressions; mismatches indicate engine version drift, not network state change.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from platform_core.reasoning_engine import run_reasoning
from platform_core.reasoning_models import Observation, ProofResult, ReasoningRun
from platform_core.storage import append_jsonl, iter_jsonl, platform_data_dir

REASONING_AUDIT_FILE = "reasoning_runs.jsonl"


def reasoning_audit_path(path: Path | None = None) -> Path:
    """Resolve the reasoning audit JSONL path."""
    return path or platform_data_dir() / REASONING_AUDIT_FILE


def to_audit_record(run: ReasoningRun) -> dict[str, Any]:
    """Serialize a reasoning run into a replayable audit record."""
    return {
        "record_type": "reasoning_run",
        "version_metadata": run.version_metadata,
        "run": run.model_dump(mode="json"),
        "raw_observations": [obs.model_dump(mode="json") for obs in run.raw_observations],
        "normalized_signals": run.normalized_signals,
        "detected_events": [event.model_dump(mode="json") for event in run.detected_events],
        "state_transitions": [
            transition.model_dump(mode="json") for transition in run.state_transitions
        ],
        "canonical_state_path": run.canonical_state_path,
        "canonical_state_transitions": run.canonical_state_transitions,
        "hypothesis_ranking": run.hypothesis_ranking,
        "evidence_tree": run.evidence_tree.model_dump(mode="json"),
        "proof_result": run.proof_result.model_dump(mode="json"),
        "policy_decision": run.policy_decision.model_dump(mode="json"),
        "recommended_next_test": run.recommended_next_test,
        "remediation_preview": run.remediation_preview,
        "limitations": run.limitations,
    }


def append_reasoning_run(run: ReasoningRun, *, path: Path | None = None) -> Path:
    """Append one reasoning run to JSONL.

    Args:
        run: Reasoning run to persist.
        path: Optional test path.

    Returns:
        Path written.
    """
    out = reasoning_audit_path(path)
    append_jsonl(out, to_audit_record(run))
    return out


def iter_reasoning_records(path: Path | None = None) -> Iterator[dict[str, Any]]:
    """Yield reasoning audit records."""
    yield from iter_jsonl(reasoning_audit_path(path))


def replay_reasoning_record(record: dict[str, Any]) -> ReasoningRun:
    """Recompute a reasoning run from stored observations and proof result only.

    Args:
        record: Audit record produced by :func:`to_audit_record`.

    Returns:
        Recomputed reasoning run. The machine is not probed.
    """
    run_blob = record.get("run") or {}
    observations_blob = record.get("raw_observations") or run_blob.get("raw_observations") or []
    observations = [Observation(**item) for item in observations_blob if isinstance(item, dict)]
    proof_blob = record.get("proof_result") or run_blob.get("proof_result") or {}
    proof = ProofResult(**proof_blob) if isinstance(proof_blob, dict) else ProofResult()
    policy_blob = record.get("policy_decision") or run_blob.get("policy_decision") or {}
    requested_action = (
        policy_blob.get("requested_action") if isinstance(policy_blob, dict) else None
    )
    codes = policy_blob.get("reason_codes") or [] if isinstance(policy_blob, dict) else []
    explicit_confirmation = bool(
        isinstance(policy_blob, dict)
        and (
            "CONFIRMED_SAFE_TIER_WITH_CONFIRMATION" in codes
            or "confirmed_proof_safe_action_confirmation_present" in codes
        )
    )
    return run_reasoning(
        observations,
        proof_result=proof,
        requested_action=requested_action,
        explicit_confirmation=explicit_confirmation,
        source="replay",
        run_id=str(run_blob.get("id") or record.get("run_id") or ""),
    )
