"""Signal conflict detection — weak evidence must not imply causation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceConflict:
    """Represent the evidence conflict type.

    Key fields:
        code: Structured value carried by this type.
        description: Structured value carried by this type.
        severity: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    code: str
    description: str
    severity: str  # low | medium | high


def detect_conflicts(signals: dict[str, Any]) -> list[EvidenceConflict]:
    """Return observable conflicts that limit evidence upgrades."""
    conflicts: list[EvidenceConflict] = []

    def truthy(key: str) -> bool:
        v = signals.get(key)
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.strip().lower() in {"1", "true", "yes", "on"}
        return bool(v)

    dns_ok = truthy("dns_ok")
    http_fail = truthy("browser_https_failed") or truthy("http_failed")
    if dns_ok and http_fail:
        conflicts.append(
            EvidenceConflict(
                code="DNS_OK_HTTP_FAIL",
                description="DNS resolves but HTTP path fails — likely L7/proxy/TLS, not DNS.",
                severity="medium",
            )
        )

    tcp_ok = truthy("tcp_ok") or truthy("tcp_443_ok")
    browser_fail = truthy("browser_https_failed")
    if tcp_ok and browser_fail:
        conflicts.append(
            EvidenceConflict(
                code="TCP_OK_BROWSER_FAIL",
                description="TCP succeeds but browser path fails — inspect proxy/TLS/app layer.",
                severity="medium",
            )
        )

    proxy_on = truthy("wininet_proxy_enabled") or truthy("proxy_enable")
    no_listener = truthy("proxy_enabled_no_listener")
    if proxy_on and no_listener:
        conflicts.append(
            EvidenceConflict(
                code="PROXY_ON_NO_LISTENER",
                description="Proxy enabled but no localhost listener observed — stale config or remote proxy.",
                severity="high",
            )
        )

    has_listener = truthy("listener_on_proxy_port") or truthy("listener_correlation")
    no_writer = not truthy("sysmon_event_13") and not truthy("registry_writer_observed")
    if has_listener and no_writer:
        conflicts.append(
            EvidenceConflict(
                code="LISTENER_NO_WRITER_PROOF",
                description="Listener correlated but registry writer telemetry missing — not causation proof.",
                severity="high",
            )
        )

    return conflicts
