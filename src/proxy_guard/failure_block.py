"""Structured proxy-related failure records for audits and diagnose JSON output.

These are WinINET-focused **diagnostic blocks**, not the ``failure_system`` package's persisted
artifacts. Copy fields into JSONL audits or platform payloads as needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ProxyFailureSeverity = Literal["info", "warning", "error"]
ProxyRiskLevel = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class ProxyFailureBlock:
    """One machine-consumable failure narrative for HKCU WinINET proxy conditions."""

    failure_id: str
    severity: ProxyFailureSeverity
    signals: dict[str, Any]
    attribution: dict[str, Any]
    likely_causes: tuple[str, ...]
    recommended_action: str
    risk_level: ProxyRiskLevel
    safety_boundary: str
    rollback_plan: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable mapping (stable keys for CLI ``--json``)."""
        return {
            "failure_id": self.failure_id,
            "severity": self.severity,
            "signals": dict(self.signals),
            "attribution": dict(self.attribution),
            "likely_causes": list(self.likely_causes),
            "recommended_action": self.recommended_action,
            "risk_level": self.risk_level,
            "safety_boundary": self.safety_boundary,
            "rollback_plan": dict(self.rollback_plan),
        }


def _empty_rollback() -> dict[str, Any]:
    return {"type": "wininet_hkcu_snapshot", "notes": "Capture snapshot before changes; use proxy-rollback."}


def build_proxy_failure_blocks(
    *,
    proxy_enable: int | None,
    parsed_proxy_dict: dict[str, Any],
    localhost_attribution: dict[str, Any] | None = None,
) -> tuple[ProxyFailureBlock, ...]:
    """Derive zero or more :class:`ProxyFailureBlock` rows from registry + parser state.

    Args:
        proxy_enable: Raw ``ProxyEnable`` dword or None if unreadable.
        parsed_proxy_dict: Output of :meth:`ParsedProxy.to_dict`.
        localhost_attribution: Optional structured listener attribution (see ``localhost_attribution``).

    Returns:
        Tuple of blocks sorted by severity (error, warning, info).
    """
    blocks: list[ProxyFailureBlock] = []
    enabled = proxy_enable == 1
    is_malformed = bool(parsed_proxy_dict.get("is_malformed"))
    is_localhost = bool(parsed_proxy_dict.get("is_localhost_proxy"))
    port = parsed_proxy_dict.get("localhost_port")
    mode = str(parsed_proxy_dict.get("proxy_mode") or "")
    raw = parsed_proxy_dict.get("raw")

    listen_explicit: bool | None = None
    if localhost_attribution is not None and "listener_found" in localhost_attribution:
        listen_explicit = bool(localhost_attribution["listener_found"])

    if is_malformed and enabled:
        blocks.append(
            ProxyFailureBlock(
                failure_id="wininet.proxy.malformed",
                severity="error",
                signals={
                    "proxy_enable": proxy_enable,
                    "proxy_server_raw": raw,
                    "proxy_mode": mode,
                },
                attribution={"method": "registry_and_parser", "notes": "ProxyServer string did not parse cleanly."},
                likely_causes=(
                    "Corrupt or partial ProxyServer value",
                    "Legacy or third-party tool wrote an invalid string",
                ),
                recommended_action="Review HKCU\\\\...\\\\Internet Settings\\\\ProxyServer; capture snapshot before edit.",
                risk_level="medium",
                safety_boundary="Do not auto-delete keys; use guided reg add/delete with confirmation.",
                rollback_plan=_empty_rollback(),
            )
        )

    if enabled and is_localhost and listen_explicit is False:
        blocks.append(
            ProxyFailureBlock(
                failure_id="wininet.localhost_proxy.dead_port",
                severity="warning",
                signals={
                    "proxy_enable": proxy_enable,
                    "localhost_port": port,
                    "proxy_mode": mode,
                    "proxy_server_raw": raw,
                },
                attribution=dict(localhost_attribution or {}),
                likely_causes=(
                    "Previous proxy exited but WinINET proxy left enabled",
                    "Port migrated or clash between tools",
                    "Race: listener starting after probe",
                ),
                recommended_action="If traffic fails, consider disabling HKCU proxy after snapshot or restarting the listener process.",
                risk_level="high",
                safety_boundary="Do not disable firewall or adapters; HKCU-only changes with confirmation.",
                rollback_plan=_empty_rollback(),
            )
        )

    if enabled and is_localhost and listen_explicit is not False:
        # ``listen_explicit is False`` is handled exclusively by ``dead_port`` above.
        # ``None`` (listener state unknown / probe skipped) still emits generic localhost.enabled.
        blocks.append(
            ProxyFailureBlock(
                failure_id="wininet.localhost_proxy.enabled",
                severity="warning",
                signals={
                    "proxy_enable": proxy_enable,
                    "localhost_port": port,
                    "proxy_mode": mode,
                    "proxy_server_raw": raw,
                },
                attribution=dict(localhost_attribution or {"method": "not_evaluated"}),
                likely_causes=(
                    "Local proxy or tunnel (Clash, v2ray, Fiddler, corporate inspection client)",
                    "Dev tool forcing loopback forwarding",
                ),
                recommended_action="Confirm intended software; inspect listener attribution; snapshot before disabling.",
                risk_level="high",
                safety_boundary="Heuristic attribution is not proof of the registry writer.",
                rollback_plan=_empty_rollback(),
            )
        )

    if enabled and not is_localhost and not is_malformed and mode not in {"missing"}:
        blocks.append(
            ProxyFailureBlock(
                failure_id="wininet.proxy.enabled.external",
                severity="info",
                signals={
                    "proxy_enable": proxy_enable,
                    "proxy_mode": mode,
                    "proxy_server_raw": raw,
                },
                attribution={"method": "registry_snapshot_only"},
                likely_causes=("Enterprise PAC or explicit corporate proxy", "User-configured upstream proxy"),
                recommended_action="Validate policy intent; snapshot before manual changes.",
                risk_level="medium",
                safety_boundary="Do not exfiltrate proxy URLs beyond local audits.",
                rollback_plan=_empty_rollback(),
            )
        )

    order = {"error": 0, "warning": 1, "info": 2}
    blocks.sort(key=lambda b: order.get(b.severity, 9))
    return tuple(blocks)
