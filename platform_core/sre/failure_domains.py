"""Failure domain isolation — bulkheads, circuit breakers, explicit degradation."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar

from platform_core.reliability.resilience import CircuitBreaker

from .event_store import append_domain_event

T = TypeVar("T")


class FailureDomain(str, Enum):
    """Bounded contexts — failures must not cascade across domains."""

    TELEMETRY_INGEST = "telemetry_ingest"
    STATE_MACHINE = "state_machine"
    HYPOTHESIS_ENGINE = "hypothesis_engine"
    POLICY_ENGINE = "policy_engine"
    REMEDIATION = "remediation"
    AUDIT = "audit"
    INVESTIGATION = "investigation"


@dataclass
class DomainHealth:
    """Represent DomainHealth data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    domain: FailureDomain
    state: str  # closed | open | half_open
    failure_count: int = 0
    last_failure_at: float | None = None
    degraded: bool = False
    message: str = ""


# Process-wide domain circuit breakers (correctness: explicit state, not hidden retries)
_BREAKERS: dict[FailureDomain, CircuitBreaker] = {
    d: CircuitBreaker(failure_threshold=5, recovery_timeout_seconds=60.0) for d in FailureDomain
}

_DOMAIN_HEALTH: dict[FailureDomain, DomainHealth] = {
    d: DomainHealth(domain=d, state="closed") for d in FailureDomain
}


class DomainDegradedError(RuntimeError):
    """Raised when a failure domain circuit is open — caller must degrade explicitly."""

    def __init__(self, domain: FailureDomain, message: str = "") -> None:
        """Initialize the DomainDegradedError instance.

        Args:
            domain: Value supplied by the caller for domain.
            message: Value supplied by the caller for message.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self.domain = domain
        super().__init__(message or f"failure domain {domain.value} is degraded")


def get_domain_health() -> list[DomainHealth]:
    """Get domain health for toolkit workflows.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    out: list[DomainHealth] = []
    for domain, cb in _BREAKERS.items():
        h = _DOMAIN_HEALTH[domain]
        h.state = cb.state
        h.degraded = cb.state == "open"
        out.append(h)
    return out


def _audit_circuit_transition(
    domain: FailureDomain,
    *,
    opened: bool,
    correlation_id: str,
    reason: str,
) -> None:
    try:
        append_domain_event(
            aggregate_id=f"domain:{domain.value}",
            aggregate_type="audit",
            event_type="domain.circuit_opened" if opened else "domain.circuit_closed",
            correlation_id=correlation_id,
            failure_domain=domain.value,  # type: ignore[arg-type]
            payload={"reason": reason, "domain": domain.value},
        )
    except Exception:
        pass  # audit failure must not mask original error path


def execute_in_domain(
    domain: FailureDomain,
    fn: Callable[[], T],
    *,
    correlation_id: str = "system",
    fallback: T | None = None,
    allow_degraded_return: bool = False,
) -> T:
    """Execute work inside a failure domain bulkhead.

    Raises DomainDegradedError when circuit is open unless allow_degraded_return.
    Records circuit transitions to canonical event log.
    """
    cb = _BREAKERS[domain]
    health = _DOMAIN_HEALTH[domain]

    if cb.state == "open":
        health.degraded = True
        health.message = f"circuit open for {domain.value}"
        if allow_degraded_return and fallback is not None:
            return fallback
        raise DomainDegradedError(domain, health.message)

    try:
        result = fn()
        cb._failures = 0  # noqa: SLF001 — intentional domain health reset on success
        if cb.state == "half_open":
            cb.state = "closed"
        health.failure_count = 0
        health.degraded = False
        health.message = ""
        return result
    except DomainDegradedError:
        raise
    except Exception as exc:
        health.failure_count += 1
        health.last_failure_at = time.monotonic()
        cb._failures += 1  # noqa: SLF001
        if cb._failures >= cb.failure_threshold:
            cb.state = "open"
            cb._opened_at = time.monotonic()
            health.degraded = True
            health.message = str(exc)[:200]
            _audit_circuit_transition(
                domain, opened=True, correlation_id=correlation_id, reason=health.message
            )
        if allow_degraded_return and fallback is not None:
            return fallback
        raise


def reset_domains_for_tests() -> None:
    """Reset circuit breakers — test isolation only."""
    for domain in FailureDomain:
        _BREAKERS[domain] = CircuitBreaker(failure_threshold=5, recovery_timeout_seconds=60.0)
        _DOMAIN_HEALTH[domain] = DomainHealth(domain=domain, state="closed")
