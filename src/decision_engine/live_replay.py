"""Backward compatibility shim; canonical implementation: :mod:`src.audit.replay`."""

from __future__ import annotations

from ..audit.replay import (
    DECISION_RUNS_LOG,
    SCHEMA_VERSION,
    SchemaVersion,
    build_replay_report,
    find_decision_run,
    format_replay_flow_text,
    iter_decision_runs_jsonl,
    live_network_snapshot_from_observations,
    proof_result_from_stored,
)

__all__ = [
    "DECISION_RUNS_LOG",
    "SCHEMA_VERSION",
    "SchemaVersion",
    "build_replay_report",
    "find_decision_run",
    "format_replay_flow_text",
    "iter_decision_runs_jsonl",
    "live_network_snapshot_from_observations",
    "proof_result_from_stored",
]
