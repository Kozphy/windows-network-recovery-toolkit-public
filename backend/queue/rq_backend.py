"""Redis RQ queue backend."""

from __future__ import annotations

import logging
import os
import uuid

from backend.queue.protocol import JobRef, JobStatus

_log = logging.getLogger(__name__)

_IDEMPOTENCY: dict[str, str] = {}


class RQQueueBackend:
    """Represent r q queue backend data used by the toolkit.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    def __init__(self) -> None:
        """Initialize the object with caller supplied state.

        Args:
            None.

        Returns:
            None.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        from redis import Redis
        from rq import Queue

        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = Redis.from_url(url)
        self._queue = Queue("trisk", connection=self._redis)

    def enqueue_classification_job(self, *, event_id: str, idempotency_key: str) -> JobRef:
        """Enqueue classification job.

        Args:
            event_id: The event id value supplied by the caller.
            idempotency_key: The idempotency key value supplied by the caller.

        Returns:
            The JobRef result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        if idempotency_key in _IDEMPOTENCY:
            job_id = _IDEMPOTENCY[idempotency_key]
            return JobRef(job_id=job_id, idempotency_key=idempotency_key, status=JobStatus.QUEUED)

        from backend.workers.classifier_worker import run_classification_job

        job = self._queue.enqueue(run_classification_job, event_id, job_id=idempotency_key[:32])
        job_id = job.id or f"rq-{uuid.uuid4().hex[:12]}"
        _IDEMPOTENCY[idempotency_key] = job_id
        _log.info("job_lifecycle event=queued job_id=%s event_id=%s", job_id, event_id)
        return JobRef(job_id=job_id, idempotency_key=idempotency_key, status=JobStatus.QUEUED)

    def get_job_status(self, job_id: str) -> JobStatus:
        """Get job status.

        Args:
            job_id: The job id value supplied by the caller.

        Returns:
            The JobStatus result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        from rq.job import Job

        try:
            job = Job.fetch(job_id, connection=self._redis)
        except Exception:
            return JobStatus.FAILED
        if job.is_finished:
            return JobStatus.SUCCEEDED
        if job.is_failed:
            return JobStatus.FAILED
        if job.is_started:
            return JobStatus.STARTED
        return JobStatus.QUEUED

    def cancel_job(self, job_id: str) -> bool:
        """Cancel job.

        Args:
            job_id: The job id value supplied by the caller.

        Returns:
            The bool result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        from rq.job import Job

        try:
            job = Job.fetch(job_id, connection=self._redis)
            job.cancel()
            return True
        except Exception:
            return False
