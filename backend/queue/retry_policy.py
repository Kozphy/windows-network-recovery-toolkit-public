"""Bounded retry policy for queue workers."""

from __future__ import annotations

MAX_RETRIES = 3
BACKOFF_SECONDS = (1, 5, 15)


def should_retry(attempt: int) -> bool:
    """Should retry.

    Args:
        attempt: The attempt value supplied by the caller.

    Returns:
        The bool result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return attempt < MAX_RETRIES


def backoff_seconds(attempt: int) -> int:
    """Backoff seconds.

    Args:
        attempt: The attempt value supplied by the caller.

    Returns:
        Integer process exit code or status value.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if attempt < 0:
        return BACKOFF_SECONDS[0]
    return BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)]
