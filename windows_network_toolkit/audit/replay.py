"""Replay JSONL evidence fixtures through the incident pipeline.

Module responsibility:
    Provides three functions for deterministic fixture-based pipeline replay:
    ``replay_jsonl`` (returns a ``PipelineResult``), ``replay_to_dict`` (returns
    the same result serialised to a plain dict), and ``load_jsonl_signals``
    (extracts a flat signal dict from a JSONL file for direct injection).

System placement:
    Called by the ``replay`` CLI command, integration tests, and operator scripts
    that need to re-run historical evidence through the current pipeline logic
    to verify classification or policy stability.

Key invariants:
    ``replay_jsonl`` and ``replay_to_dict`` default to ``dry_run=True``;
    passing ``dry_run=False`` may trigger audit writes but never registry mutations
    from within this module.  ``load_jsonl_signals`` is read-only.

Side effects:
    ``replay_jsonl`` / ``replay_to_dict``: reads the fixture JSONL file and may
    write a new audit record via ``run_incident_pipeline``.  ``load_jsonl_signals``:
    reads the JSONL file; no writes.

Failure modes:
    ``FileNotFoundError`` or ``json.JSONDecodeError`` if the fixture file is
    missing or contains invalid JSON lines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from windows_network_toolkit.pipeline import PipelineResult, run_incident_pipeline


def _incident_type_value(decision: Any) -> str:
    """Extract a string representation of ``decision.incident_type``.

    Args:
        decision: Pipeline decision object; must have an ``incident_type``
            attribute that is either an enum (with ``.value``) or a plain str.

    Returns:
        The ``.value`` of the enum, or ``str(incident_type)`` as a fallback.
    """
    incident_type = decision.incident_type
    return incident_type.value if hasattr(incident_type, "value") else str(incident_type)


def replay_jsonl(path: Path | str, *, dry_run: bool = True) -> PipelineResult:
    """Replay a JSONL evidence fixture through the incident pipeline.

    Args:
        path: Path to the JSONL fixture file containing evidence signals or
            canonical audit records to replay.
        dry_run: When ``True`` (default), the pipeline runs in preview mode
            without authorising live remediation.

    Returns:
        A ``PipelineResult`` containing the bundle, decision, policy outcome,
        remediation preview, timeline, and audit record.

    Side effects:
        Reads the fixture file.  May write a new audit record depending on
        pipeline configuration.
    """
    return run_incident_pipeline(jsonl_path=path, dry_run=dry_run)


def replay_to_dict(path: Path | str, *, dry_run: bool = True) -> dict[str, Any]:
    """Replay a JSONL fixture and return the pipeline result as a plain dict.

    Convenience wrapper around ``replay_jsonl`` for callers that need a
    JSON-serialisable output (e.g. CLI command handlers, REST endpoints).

    Args:
        path: Path to the JSONL fixture file.
        dry_run: Forwarded to ``replay_jsonl``.

    Returns:
        A dict with ``incident_id``, ``timeline``, ``incident_type``,
        ``confidence``, ``decision``, ``policy``, ``remediation``, and
        ``audit`` fields.

    Side effects:
        Same as ``replay_jsonl``.
    """
    result = replay_jsonl(path, dry_run=dry_run)
    return {
        "incident_id": result.bundle.incident_id,
        "timeline": result.timeline,
        "incident_type": _incident_type_value(result.decision),
        "confidence": result.decision.confidence,
        "decision": result.decision.model_dump(),
        "policy": result.policy,
        "remediation": result.remediation,
        "audit": result.audit_record,
    }


def load_jsonl_signals(path: Path | str) -> dict[str, Any]:
    """Load a JSONL file and extract a flat signal dict for pipeline injection.

    Supports three record shapes:
    - ``{"signal": "name", "observed_value": ...}`` — explicit signal records.
    - ``{"name": "key", "value": ...}`` — named-value records.
    - Any other dict — merged directly, excluding ``timestamp`` / ``timestamp_utc``.

    Args:
        path: Path to the JSONL file.  All lines must be valid JSON dicts;
            blank lines are skipped.

    Returns:
        A flat dict mapping signal names to observed values.  Later records
        overwrite earlier ones for the same key.

    Side effects:
        Reads the entire file into memory; no writes.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If any non-blank line is not valid JSON.
    """
    signals: dict[str, Any] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if isinstance(row, dict):
            if "signal" in row:
                signals[str(row["signal"])] = row.get("observed_value", row.get("value"))
            elif "name" in row:
                signals[str(row["name"])] = row.get("value")
            else:
                signals.update(
                    {k: v for k, v in row.items() if k not in {"timestamp", "timestamp_utc"}}
                )
    return signals
