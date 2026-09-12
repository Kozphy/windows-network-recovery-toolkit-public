"""Endpoint evidence collection — OS abstraction for read-only observe-only probes.

Module responsibility:
    Canonical factory and contracts for endpoint evidence bundles used by agents,
    APIs, and cross-platform diagnostics. Delegates to ``platform_core.network_diagnostics``
    for live observations — does not duplicate ``windows_network_toolkit/collectors/``.

System placement:
    Phase 1 of enterprise hardening ([docs/enterprise-hardening-roadmap.md](../../docs/enterprise-hardening-roadmap.md)).
    Consumed by future agent CLI (Phase 2) and existing ``platform_core.os_probe`` callers.

Key invariants:
    * Collection is read-only; no registry mutation or remediation in this package.
    * ``platform_support_level`` is honest: FULL (Windows proxy path), PARTIAL (Linux/macOS foundation), NOT_SUPPORTED (unknown).
    * Every bundle includes ``limitations[]``; non-Windows bundles state no WinINET/WinHTTP parity.

Side effects:
    Subprocess/socket reads only via delegated network diagnostics providers.

Audit Notes:
    Mis-labeling PARTIAL as FULL would over-claim proof tiers — tests assert support levels per OS.
"""

from src.platform_core.evidence_collection.factory import (
    collect_endpoint_evidence,
    get_endpoint_evidence_collector,
)
from src.platform_core.evidence_collection.models import (
    EndpointEvidenceBundle,
    PlatformSupportLevel,
)
from src.platform_core.evidence_collection.normalize import (
    assert_honest_platform_labels,
    normalize_evidence_bundle,
    normalize_observation_row,
)

__all__ = [
    "EndpointEvidenceBundle",
    "PlatformSupportLevel",
    "assert_honest_platform_labels",
    "collect_endpoint_evidence",
    "get_endpoint_evidence_collector",
    "normalize_evidence_bundle",
    "normalize_observation_row",
]
