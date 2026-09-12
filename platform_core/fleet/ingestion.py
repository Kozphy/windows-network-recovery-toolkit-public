"""Distributed ingestion gateway — validate, dedupe, partition, publish."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Protocol

from .deduplication import DedupDecision, IdempotencyStore, InMemoryIdempotencyStore
from .models import FleetEventEnvelope
from .partitioning import assign_partition, topic_for_stream


class EventPublisher(Protocol):
    """Stream publisher adapter (Kafka, Redpanda, NATS)."""

    def publish(self, topic: str, key: str, value: bytes, *, headers: dict[str, str]) -> None:
        """Provide publish behavior for toolkit workflows.

        Args:
            topic: Value supplied by the caller for topic.
            key: Value supplied by the caller for key.
            value: Value supplied by the caller for value.
            headers: Value supplied by the caller for headers.

        Returns:
            None.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        ...


@dataclass
class IngestResult:
    """Represent IngestResult data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    accepted: bool
    event_id: str
    partition_id: int
    topic: str
    dedup: DedupDecision
    published: bool = False


@dataclass
class FleetIngestGateway:
    """Regional ingest gateway — single entry point for agent event batches.

    Flow:
        1. Validate envelope schema
        2. Dedup via IdempotencyStore
        3. Assign partition
        4. Publish to stream (or append local WAL in FLEET_MODE=local)
    """

    dedup_store: IdempotencyStore = field(default_factory=InMemoryIdempotencyStore)
    publisher: EventPublisher | None = None

    def ingest_one(self, envelope: FleetEventEnvelope) -> IngestResult:
        """Ingest one for toolkit workflows.

        Args:
            envelope: Value supplied by the caller for envelope.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        finalized = envelope.finalize()
        dedup = self.dedup_store.check_and_record(finalized)

        if dedup.outcome == "conflict":
            return IngestResult(
                accepted=False,
                event_id=finalized.event_id,
                partition_id=-1,
                topic="",
                dedup=dedup,
                published=False,
            )

        if dedup.outcome == "duplicate":
            part = assign_partition(finalized.tenant.tenant_id, finalized.endpoint_id_hash)
            topic = topic_for_stream(finalized.stream, finalized.tenant.tier)
            return IngestResult(
                accepted=True,
                event_id=finalized.event_id,
                partition_id=part.partition_id,
                topic=topic,
                dedup=dedup,
                published=False,
            )

        part = assign_partition(finalized.tenant.tenant_id, finalized.endpoint_id_hash)
        topic = topic_for_stream(finalized.stream, finalized.tenant.tier)
        published = self._publish(finalized, topic, part.partition_id)

        return IngestResult(
            accepted=True,
            event_id=finalized.event_id,
            partition_id=part.partition_id,
            topic=topic,
            dedup=dedup,
            published=published,
        )

    def ingest_batch(self, envelopes: list[FleetEventEnvelope]) -> list[IngestResult]:
        """Ingest batch for toolkit workflows.

        Args:
            envelopes: Value supplied by the caller for envelopes.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return [self.ingest_one(e) for e in envelopes]

    def _publish(self, envelope: FleetEventEnvelope, topic: str, partition_id: int) -> bool:
        mode = os.environ.get("FLEET_MODE", "local")
        if mode == "local":
            self._append_local_wal(envelope)
            return True
        if self.publisher is None:
            return False
        import json

        headers = {
            "tenant_id": envelope.tenant.tenant_id,
            "event_id": envelope.event_id,
            "partition_id": str(partition_id),
            "schema_version": envelope.schema_version,
        }
        self.publisher.publish(
            topic,
            envelope.partition_key,
            json.dumps(envelope.model_dump(mode="json")).encode("utf-8"),
            headers=headers,
        )
        return True

    def _append_local_wal(self, envelope: FleetEventEnvelope) -> None:
        from platform_core import storage

        storage.append_jsonl(
            storage.platform_data_dir() / "fleet_ingest_wal.jsonl",
            envelope.model_dump(mode="json"),
        )
