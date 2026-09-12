"""Partition-scoped replay at scale — batch workers, deterministic projections."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

ReplayScope = Literal["incident", "endpoint", "tenant_partition", "decision_run"]


@dataclass(frozen=True)
class ReplayJobSpec:
    """Unit of replay work schedulable on a partition worker."""

    job_id: str
    tenant_id: str
    partition_id: int
    scope: ReplayScope
    resource_id: str
    time_start_utc: str
    time_end_utc: str
    correlation_id: str = ""
    deterministic_seed: str = ""

    @classmethod
    def for_incident(
        cls,
        *,
        job_id: str,
        tenant_id: str,
        incident_id: str,
        partition_id: int,
        time_start_utc: str,
        time_end_utc: str,
    ) -> ReplayJobSpec:
        """Provide for incident behavior for toolkit workflows.

        Args:
            job_id: Value supplied by the caller for job id.
            tenant_id: Value supplied by the caller for tenant id.
            incident_id: Value supplied by the caller for incident id.
            partition_id: Value supplied by the caller for partition id.
            time_start_utc: Value supplied by the caller for time start utc.
            time_end_utc: Value supplied by the caller for time end utc.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        seed = hashlib.sha256(f"{tenant_id}:{incident_id}".encode()).hexdigest()[:16]
        return cls(
            job_id=job_id,
            tenant_id=tenant_id,
            partition_id=partition_id,
            scope="incident",
            resource_id=incident_id,
            time_start_utc=time_start_utc,
            time_end_utc=time_end_utc,
            correlation_id=incident_id,
            deterministic_seed=seed,
        )


@dataclass
class ReplayJobResult:
    """Represent ReplayJobResult data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    job_id: str
    parity: dict[str, bool]
    event_count: int
    duration_ms: float
    limitations: list[str] = field(default_factory=list)
    output: dict[str, Any] = field(default_factory=dict)


class ReplayCoordinator:
    """Coordinates replay jobs without loading entire tenant history on one host.

    At scale:
        - Control plane enqueues ReplayJobSpec per partition to ``erp.replay.jobs``
        - Workers consume, read partition-compacted topic + cold store
        - Results written to ``erp.replay.results`` + object store artifact
    """

    def __init__(self) -> None:
        """Initialize the ReplayCoordinator instance.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self._results: dict[str, ReplayJobResult] = {}

    def enqueue(self, spec: ReplayJobSpec) -> str:
        """Provide enqueue behavior for toolkit workflows.

        Args:
            spec: Value supplied by the caller for spec.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        return spec.job_id

    def run_local(self, spec: ReplayJobSpec) -> ReplayJobResult:
        """Local/dev replay — delegates to SRE TimeTravelReplay when scope=incident."""
        import time

        t0 = time.perf_counter()
        limitations = [
            "Replay at scale uses partition workers; local mode scans WAL only.",
            "Observation != Proof — replay recomputes policy, does not re-probe hosts.",
        ]
        output: dict[str, Any] = {}
        parity: dict[str, bool] = {}

        if spec.scope == "incident":
            from platform_core.sre.projector import rebuild_incident

            proj = rebuild_incident(spec.resource_id)
            if proj.event_count == 0:
                parity = {"found": False}
                output = {"incident_id": spec.resource_id}
            else:
                parity = {"found": True, "phase_resolved": proj.phase.value == "RESOLVED"}
                output = proj.model_dump(mode="json")
        elif spec.scope == "decision_run":
            from platform_core.reliability.time_travel import TimeTravelReplay

            try:
                result = TimeTravelReplay.load_and_replay(spec.resource_id)
                parity = result.parity
                output = result.to_jsonable()
            except KeyError:
                parity = {"found": False}

        elapsed = (time.perf_counter() - t0) * 1000
        job_result = ReplayJobResult(
            job_id=spec.job_id,
            parity=parity,
            event_count=output.get("event_count", 0)
            if isinstance(output.get("event_count"), int)
            else 0,
            duration_ms=round(elapsed, 2),
            limitations=limitations,
            output=output,
        )
        self._results[spec.job_id] = job_result
        return job_result

    def get_result(self, job_id: str) -> ReplayJobResult | None:
        """Get result for toolkit workflows.

        Args:
            job_id: Value supplied by the caller for job id.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return self._results.get(job_id)
