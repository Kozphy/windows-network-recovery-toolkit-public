"""Deterministic partition assignment for 100k+ endpoint fleets."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


def partition_count() -> int:
    """Total stream partitions — override via FLEET_PARTITION_COUNT (default 256)."""
    raw = os.environ.get("FLEET_PARTITION_COUNT", "256")
    try:
        n = int(raw)
    except ValueError:
        n = 256
    return max(16, min(n, 4096))


@dataclass(frozen=True)
class PartitionKey:
    """Represent PartitionKey data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    tenant_id: str
    endpoint_id_hash: str
    partition_id: int
    partition_total: int

    @property
    def kafka_key(self) -> str:
        """Provide kafka key behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return f"{self.tenant_id}:{self.endpoint_id_hash}"


def assign_partition(
    tenant_id: str,
    endpoint_id_hash: str,
    *,
    total: int | None = None,
) -> PartitionKey:
    """Murmur-style stable hash — same endpoint always maps to same partition."""
    total_parts = total or partition_count()
    material = f"{tenant_id}:{endpoint_id_hash.lower()}".encode()
    digest = hashlib.blake2b(material, digest_size=8).digest()
    pid = int.from_bytes(digest, "big") % total_parts
    return PartitionKey(
        tenant_id=tenant_id,
        endpoint_id_hash=endpoint_id_hash.lower(),
        partition_id=pid,
        partition_total=total_parts,
    )


def topic_for_stream(stream: str, tenant_tier: str = "standard") -> str:
    """Topic naming convention — enterprise tenants may get dedicated topics."""
    prefix = os.environ.get("FLEET_TOPIC_PREFIX", "erp")
    if tenant_tier == "enterprise":
        return f"{prefix}.{stream}.enterprise"
    return f"{prefix}.{stream}.shared"
