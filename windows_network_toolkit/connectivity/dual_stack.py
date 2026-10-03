"""Classify independently collected IPv4/IPv6 connectivity evidence.

This module sits between evidence collectors and policy/reporting consumers. It
does not perform DNS, socket, registry, or network configuration operations; it
only evaluates the supplied evidence and returns a replayable assessment.

The classifier treats ``NOT_TESTED`` as missing evidence rather than success.
Consequently, callers must run all required checks before interpreting a path as
healthy. A classification is an evidence label, not proof of root cause or a
remediation authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PathState(StrEnum):
    """Outcome of one family-specific connectivity check."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_TESTED = "NOT_TESTED"


class DualStackClass(StrEnum):
    """Deterministic labels emitted by :func:`classify_dual_stack`."""

    HEALTHY = "HEALTHY"
    IPV6_PATH_FAILURE = "IPV6_PATH_FAILURE"
    IPV4_PATH_FAILURE = "IPV4_PATH_FAILURE"
    GENERAL_NETWORK_FAILURE = "GENERAL_NETWORK_FAILURE"
    DEGRADED_FALLBACK = "DEGRADED_FALLBACK"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class PathProbe:
    """Evidence summary for one IP-family path.

    Each field represents an independently collected check. ``NOT_TESTED``
    prevents missing evidence from being treated as a successful probe.

    Attributes:
        dns: Result of resolving the family-specific record.
        route: Result of finding an active default route for the family.
        tcp: Result of establishing a TCP connection.
        tls: Result of completing the TLS handshake.
        http: Result of receiving an HTTP status line.
        endpoint: Result of reaching the target endpoint.
        latency_ms: Optional elapsed time for the collected path checks.
    """

    dns: PathState = PathState.NOT_TESTED
    route: PathState = PathState.NOT_TESTED
    tcp: PathState = PathState.NOT_TESTED
    tls: PathState = PathState.NOT_TESTED
    http: PathState = PathState.NOT_TESTED
    endpoint: PathState = PathState.NOT_TESTED
    latency_ms: float | None = None

    @property
    def complete(self) -> bool:
        """Return whether every required check has an explicit outcome."""
        return all(
            state is not PathState.NOT_TESTED
            for state in (self.dns, self.route, self.tcp, self.tls, self.http, self.endpoint)
        )

    @property
    def passed(self) -> bool:
        """Return whether every required check passed."""
        return self.complete and all(
            state is PathState.PASS
            for state in (self.dns, self.route, self.tcp, self.tls, self.http, self.endpoint)
        )

    @property
    def failed(self) -> bool:
        """Return whether at least one check explicitly failed."""
        return any(
            state is PathState.FAIL
            for state in (self.dns, self.route, self.tcp, self.tls, self.http, self.endpoint)
        )


@dataclass(frozen=True, slots=True)
class DualStackAssessment:
    """Immutable classification result returned to policy and reporting layers.

    ``ai_connectivity_ready`` is intentionally stricter than
    ``classification == HEALTHY``: both paths must pass and fallback must not
    have been observed. This class does not claim that an AI service is healthy;
    endpoint-specific SLO and application checks remain outside this module.

    Attributes:
        classification: Deterministic outcome for the two supplied paths.
        ipv4_healthy: Whether the IPv4 probe is complete and all checks passed.
        ipv6_healthy: Whether the IPv6 probe is complete and all checks passed.
        degraded: Whether the result is anything other than ``HEALTHY``.
        fallback_detected: Whether an upstream fallback observation was supplied.
        limitations: Evidence gaps or other constraints for reviewers.
    """

    classification: DualStackClass
    ipv4_healthy: bool
    ipv6_healthy: bool
    degraded: bool
    fallback_detected: bool
    limitations: tuple[str, ...]

    @property
    def ai_connectivity_ready(self) -> bool:
        """Return strict readiness for both paths without unexpected fallback."""
        return (
            self.classification is DualStackClass.HEALTHY
            and self.ipv4_healthy
            and self.ipv6_healthy
            and not self.fallback_detected
        )


def classify_dual_stack(
    ipv4: PathProbe,
    ipv6: PathProbe,
    *,
    fallback_detected: bool = False,
) -> DualStackAssessment:
    """Classify dual-stack evidence without performing remediation.

    Args:
        ipv4: Evidence collected for the IPv4 path.
        ipv6: Evidence collected for the IPv6 path.
        fallback_detected: Whether an external observer recorded fallback
            behavior despite both paths passing.

    Returns:
        A frozen assessment with explicit health flags and limitations.

    Side effects:
        None. The function is deterministic and does not mutate its inputs.

    Classification precedence:
        1. Incomplete evidence is ``INCONCLUSIVE`` unless a concrete failure is
           already known.
        2. Two passing paths are ``HEALTHY`` or ``DEGRADED_FALLBACK``.
        3. One passing path and one failing path produces a family-specific
           failure label.
        4. Two failing paths produce ``GENERAL_NETWORK_FAILURE``.

    Audit Notes:
        Review the individual ``PathProbe`` fields and ``limitations`` before
        using the label in a report. The result does not establish causation and
        must not be used by itself to disable IPv4 or IPv6.
    """

    limitations: list[str] = []
    if not ipv4.complete:
        limitations.append("IPv4 evidence incomplete")
    if not ipv6.complete:
        limitations.append("IPv6 evidence incomplete")

    if ipv4.passed and ipv6.passed:
        classification = (
            DualStackClass.DEGRADED_FALLBACK if fallback_detected else DualStackClass.HEALTHY
        )
    elif ipv4.passed and ipv6.failed:
        classification = DualStackClass.IPV6_PATH_FAILURE
    elif ipv6.passed and ipv4.failed:
        classification = DualStackClass.IPV4_PATH_FAILURE
    elif ipv4.failed and ipv6.failed:
        classification = DualStackClass.GENERAL_NETWORK_FAILURE
    else:
        classification = DualStackClass.INCONCLUSIVE

    return DualStackAssessment(
        classification=classification,
        ipv4_healthy=ipv4.passed,
        ipv6_healthy=ipv6.passed,
        degraded=(classification is not DualStackClass.HEALTHY),
        fallback_detected=fallback_detected,
        limitations=tuple(limitations),
    )
