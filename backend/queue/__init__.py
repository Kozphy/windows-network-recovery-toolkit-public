"""Queue backend factory."""

from __future__ import annotations

import os

from backend.queue.memory_backend import MemoryQueueBackend
from backend.queue.protocol import QueueBackend


def get_queue_backend() -> QueueBackend:
    """Get queue backend.
    
    Args:
        None.
    
    Returns:
        The QueueBackend result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    backend = os.getenv("QUEUE_BACKEND", "memory").lower()
    if backend == "rq":
        from backend.queue.rq_backend import RQQueueBackend

        return RQQueueBackend()
    return MemoryQueueBackend()
