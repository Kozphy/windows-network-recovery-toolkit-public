"""Append-only event pipeline — all observations become normalized events."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from platform_core import storage

from .models import EventSourceKind, NormalizedPlatformEvent

PIPELINE_FILE = "platform_events.jsonl"


def _pipeline_path(path: Path | None = None) -> Path:
    return path or storage.platform_data_dir() / PIPELINE_FILE


def _infer_source_kind(raw: dict[str, Any]) -> EventSourceKind:
    src = str(raw.get("source") or raw.get("source_kind") or "").lower()
    if "sysmon" in src:
        return "sysmon"
    if "procmon" in src or "registry" in src:
        return "registry"
    if "etw" in src:
        return "etw"
    if "eventlog" in src or "event_log" in src:
        return "windows_event_log"
    if "network" in src or "netstat" in src or "tcp" in src:
        return "network_telemetry"
    if raw.get("source_kind") in {
        "registry",
        "sysmon",
        "etw",
        "windows_event_log",
        "network_telemetry",
        "agent",
        "cli",
        "replay",
        "fixture",
    }:
        return raw["source_kind"]  # type: ignore[return-value]
    return "agent"


def normalize_raw_observation(
    raw: dict[str, Any],
    *,
    endpoint_id: str = "local",
    source_kind: EventSourceKind | None = None,
) -> NormalizedPlatformEvent:
    """Convert a raw observation dict into a normalized platform event."""
    kind = source_kind or _infer_source_kind(raw)
    signal = str(raw.get("signal_name") or raw.get("name") or raw.get("event_type") or "unknown")
    tier = raw.get("evidence_tier") or "TIER_0_RAW_OBSERVATION"
    if raw.get("proof_status") == "CONFIRMED" or raw.get("strength") == "proof":
        tier = "TIER_3_CAUSAL_PROOF"
    elif raw.get("strength") in ("strong", "medium"):
        tier = "TIER_1_CORRELATED_SIGNAL"
    return NormalizedPlatformEvent(
        endpoint_id=endpoint_id,
        source_kind=kind,
        source_detail=str(raw.get("source_detail") or raw.get("source") or ""),
        signal_name=signal,
        signal_value=raw.get("value") if "value" in raw else raw.get("signal_value"),
        severity=raw.get("severity") or "info",  # type: ignore[arg-type]
        evidence_tier=tier,  # type: ignore[arg-type]
        observation_ids=list(raw.get("observation_ids") or []),
        limitations=list(raw.get("limitations") or []),
        payload={k: v for k, v in raw.items() if k not in {"signal_name", "value"}},
    )


def ingest_raw_observation(
    raw: dict[str, Any],
    *,
    endpoint_id: str = "local",
    path: Path | None = None,
) -> NormalizedPlatformEvent:
    """Normalize and append one event to the pipeline."""
    event = normalize_raw_observation(raw, endpoint_id=endpoint_id)
    storage.append_jsonl(_pipeline_path(path), event.model_dump(mode="json"))
    return event


class EventPipeline:
    """Append-only ingest and read API for normalized platform events."""

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the EventPipeline instance.

        Args:
            path: Value supplied by the caller for path.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self._path = _pipeline_path(path)

    def append(self, event: NormalizedPlatformEvent) -> NormalizedPlatformEvent:
        """Provide append behavior for toolkit workflows.

        Args:
            event: Value supplied by the caller for event.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        storage.append_jsonl(self._path, event.model_dump(mode="json"))
        return event

    def ingest(self, raw: dict[str, Any], *, endpoint_id: str = "local") -> NormalizedPlatformEvent:
        """Provide ingest behavior for toolkit workflows.

        Args:
            raw: Value supplied by the caller for raw.
            endpoint_id: Value supplied by the caller for endpoint id.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return ingest_raw_observation(raw, endpoint_id=endpoint_id, path=self._path)

    def ingest_batch(
        self, rows: list[dict[str, Any]], *, endpoint_id: str = "local"
    ) -> list[NormalizedPlatformEvent]:
        """Ingest batch for toolkit workflows.

        Args:
            rows: Value supplied by the caller for rows.
            endpoint_id: Value supplied by the caller for endpoint id.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        out: list[NormalizedPlatformEvent] = []
        for row in rows:
            out.append(self.ingest(row, endpoint_id=endpoint_id))
        return out

    def iter_events(
        self, *, endpoint_id: str | None = None, since: str | None = None, limit: int = 500
    ) -> Iterator[NormalizedPlatformEvent]:
        """Provide iter events behavior for toolkit workflows.

        Args:
            endpoint_id: Value supplied by the caller for endpoint id.
            since: Value supplied by the caller for since.
            limit: Value supplied by the caller for limit.

        Yields:
            Observed values produced by the iterator.

        Side effects:
            None.
        """
        count = 0
        for row in storage.iter_jsonl(self._path):
            if not isinstance(row, dict):
                continue
            if endpoint_id and row.get("endpoint_id") != endpoint_id:
                continue
            if since and str(row.get("timestamp_utc") or "") < since:
                continue
            try:
                yield NormalizedPlatformEvent(**row)
            except Exception:
                continue
            count += 1
            if count >= limit:
                break

    def load_jsonl_text(
        self, text: str, *, endpoint_id: str = "local"
    ) -> list[NormalizedPlatformEvent]:
        """Import newline-delimited JSON (e.g. replay fixture)."""
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        return [self.ingest(r, endpoint_id=endpoint_id) for r in rows if isinstance(r, dict)]
