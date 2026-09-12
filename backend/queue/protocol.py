"""Queue backend protocol — migration-ready abstraction over RQ."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class JobStatus(StrEnum):
    """Represent job status data used by the toolkit.
    
    Attributes:
        QUEUED: Field or variant describing q u e u e d evidence or state.
        STARTED: Field or variant describing s t a r t e d evidence or state.
        SUCCEEDED: Field or variant describing s u c c e e d e d evidence or state.
        FAILED: Field or variant describing f a i l e d evidence or state.
        RETRIED: Field or variant describing r e t r i e d evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    QUEUED = "queued"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RETRIED = "retried"


@dataclass(frozen=True)
class JobRef:
    """Represent job ref data used by the toolkit.
    
    Attributes:
        job_id: Field or variant describing job id evidence or state.
        idempotency_key: Field or variant describing idempotency key evidence or state.
        status: Field or variant describing status evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    job_id: str
    idempotency_key: str
    status: JobStatus


class QueueBackend(Protocol):
    """Represent queue backend data used by the toolkit.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    def enqueue_classification_job(self, *, event_id: str, idempotency_key: str) -> JobRef:
        """Enqueue classification; duplicate idempotency_key returns existing job."""

    def get_job_status(self, job_id: str) -> JobStatus:
        """Return current job status."""

    def cancel_job(self, job_id: str) -> bool:
        """Cancel if supported; return False when not supported."""
