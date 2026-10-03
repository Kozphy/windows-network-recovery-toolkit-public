"""Proxy listener and registry attribution models — diagnostic only."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ListenerClassification(StrEnum):
    """Represent the listener classification enum.

    Variants:
        NO_PROXY: Structured value carried by this enum.
        KNOWN_DEV_PROXY: Structured value carried by this enum.
        KNOWN_SECURITY_TOOL: Structured value carried by this enum.
        KNOWN_VPN_PROXY: Structured value carried by this enum.
        UNKNOWN_LOCAL_PROXY: Structured value carried by this enum.
        SUSPICIOUS_PROXY: Structured value carried by this enum.
        POSSIBLE_MITM_RISK: Structured value carried by this enum.
        DEAD_PROXY_CONFIG: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    NO_PROXY = "NO_PROXY"
    KNOWN_DEV_PROXY = "KNOWN_DEV_PROXY"
    KNOWN_SECURITY_TOOL = "KNOWN_SECURITY_TOOL"
    KNOWN_VPN_PROXY = "KNOWN_VPN_PROXY"
    UNKNOWN_LOCAL_PROXY = "UNKNOWN_LOCAL_PROXY"
    SUSPICIOUS_PROXY = "SUSPICIOUS_PROXY"
    POSSIBLE_MITM_RISK = "POSSIBLE_MITM_RISK"
    DEAD_PROXY_CONFIG = "DEAD_PROXY_CONFIG"


class ProcessAttribution(BaseModel):
    """Represent the process attribution type.

    Key fields:
        pid: Structured value carried by this type.
        parent_pid: Structured value carried by this type.
        executable_path: Structured value carried by this type.
        command_line: Structured value carried by this type.
        process_name: Structured value carried by this type.
        start_time_utc: Structured value carried by this type.
        publisher: Structured value carried by this type.
        signature_status: Structured value carried by this type.

    Side effects:
        None.
    """

    pid: int | None = None
    parent_pid: int | None = None
    executable_path: str = ""
    command_line: str = ""
    process_name: str = ""
    start_time_utc: str = ""
    publisher: str = ""
    signature_status: str = ""
    user_session: str = ""


class ProxyStateSnapshot(BaseModel):
    """Represent the proxy state snapshot type.

    Key fields:
        wininet_proxy_enable: Structured value carried by this type.
        wininet_proxy_server: Structured value carried by this type.
        wininet_proxy_override: Structured value carried by this type.
        wininet_auto_config_url: Structured value carried by this type.
        winhttp_raw: Structured value carried by this type.
        winhttp_direct_access: Structured value carried by this type.
        localhost_port: Structured value carried by this type.

    Side effects:
        None.
    """

    wininet_proxy_enable: int = 0
    wininet_proxy_server: str = ""
    wininet_proxy_override: str = ""
    wininet_auto_config_url: str = ""
    winhttp_raw: str = ""
    winhttp_direct_access: bool = True
    localhost_port: int | None = None


class AttributionSnapshot(BaseModel):
    """Read-only proxy/registry/process attribution — no mutations."""

    snapshot_id: str
    timestamp_utc: str
    proxy_state: ProxyStateSnapshot
    listener: ProcessAttribution = Field(default_factory=ProcessAttribution)
    classification: ListenerClassification = ListenerClassification.NO_PROXY
    classification_rationale: str = ""
    limitations: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.
        """
        return self.model_dump(mode="json")
