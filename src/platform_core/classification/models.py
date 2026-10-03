"""Classification enums and result models."""

from __future__ import annotations

from enum import StrEnum


class PrimaryClassification(StrEnum):
    """Represent the primary classification enum.

    Variants:
        NO_PROXY: Structured value carried by this enum.
        DEAD_PROXY_CONFIG: Structured value carried by this enum.
        LOCAL_PROXY_ACTIVE: Structured value carried by this enum.
        UNKNOWN_LOCAL_PROXY: Structured value carried by this enum.
        KNOWN_DEV_PROXY: Structured value carried by this enum.
        KNOWN_SECURITY_TOOL: Structured value carried by this enum.
        SUSPICIOUS_PROXY: Structured value carried by this enum.
        POSSIBLE_MITM_RISK: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    NO_PROXY = "NO_PROXY"
    DEAD_PROXY_CONFIG = "DEAD_PROXY_CONFIG"
    LOCAL_PROXY_ACTIVE = "LOCAL_PROXY_ACTIVE"
    UNKNOWN_LOCAL_PROXY = "UNKNOWN_LOCAL_PROXY"
    KNOWN_DEV_PROXY = "KNOWN_DEV_PROXY"
    KNOWN_SECURITY_TOOL = "KNOWN_SECURITY_TOOL"
    SUSPICIOUS_PROXY = "SUSPICIOUS_PROXY"
    POSSIBLE_MITM_RISK = "POSSIBLE_MITM_RISK"
    PAC_CONFIGURED = "PAC_CONFIGURED"
    WININET_WINHTTP_MISMATCH = "WININET_WINHTTP_MISMATCH"
    REVERTER_SUSPECTED = "REVERTER_SUSPECTED"
    ERROR_INSUFFICIENT_DATA = "ERROR_INSUFFICIENT_DATA"


class SecondarySignal(StrEnum):
    """Represent the secondary signal enum.

    Variants:
        WININET_WINHTTP_MISMATCH: Structured value carried by this enum.
        LOCALHOST_PROXY: Structured value carried by this enum.
        DEAD_LOCALHOST_PORT: Structured value carried by this enum.
        PAC_PRESENT: Structured value carried by this enum.
        UNKNOWN_LISTENER: Structured value carried by this enum.
        KNOWN_DEV_TOOL: Structured value carried by this enum.
        KNOWN_SECURITY_TOOL: Structured value carried by this enum.
        REGISTRY_REWRITE_OBSERVED: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    WININET_WINHTTP_MISMATCH = "WININET_WINHTTP_MISMATCH"
    LOCALHOST_PROXY = "LOCALHOST_PROXY"
    DEAD_LOCALHOST_PORT = "DEAD_LOCALHOST_PORT"
    PAC_PRESENT = "PAC_PRESENT"
    UNKNOWN_LISTENER = "UNKNOWN_LISTENER"
    KNOWN_DEV_TOOL = "KNOWN_DEV_TOOL"
    KNOWN_SECURITY_TOOL = "KNOWN_SECURITY_TOOL"
    REGISTRY_REWRITE_OBSERVED = "REGISTRY_REWRITE_OBSERVED"
    WRITER_LISTENER_MISMATCH = "WRITER_LISTENER_MISMATCH"
    REPEATED_PROXY_REAPPEARANCE = "REPEATED_PROXY_REAPPEARANCE"
    SUSPICIOUS_PROCESS_PATH = "SUSPICIOUS_PROCESS_PATH"
