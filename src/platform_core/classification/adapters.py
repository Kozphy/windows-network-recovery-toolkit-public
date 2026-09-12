"""Map analytics / legacy classification labels to canonical PrimaryClassification."""

from __future__ import annotations

from src.platform_core.classification.models import PrimaryClassification

_ANALYTICS_TO_PRIMARY: dict[str, PrimaryClassification] = {
    "NO_PROXY_DIRECT_OK": PrimaryClassification.NO_PROXY,
    "PROXY_FLAPPING": PrimaryClassification.REVERTER_SUSPECTED,
    "DIRECT_ONLY_WORKS": PrimaryClassification.DEAD_PROXY_CONFIG,
    "BOTH_DIRECT_AND_PROXY_FAIL": PrimaryClassification.ERROR_INSUFFICIENT_DATA,
    "BOTH_DIRECT_AND_PROXY_WORK": PrimaryClassification.LOCAL_PROXY_ACTIVE,
    "PROXY_ONLY_WORKS": PrimaryClassification.LOCAL_PROXY_ACTIVE,
    "PROXY_FORWARDING_FAILED": PrimaryClassification.DEAD_PROXY_CONFIG,
    "LISTENER_NOT_PROXY": PrimaryClassification.UNKNOWN_LOCAL_PROXY,
    "STALE_PROXY_AFTER_PROCESS_EXIT": PrimaryClassification.DEAD_PROXY_CONFIG,
    "BROKEN_LOCALHOST_PROXY": PrimaryClassification.DEAD_PROXY_CONFIG,
    "INSUFFICIENT_DATA": PrimaryClassification.ERROR_INSUFFICIENT_DATA,
    "KNOWN_CURSOR_PROXY": PrimaryClassification.KNOWN_DEV_PROXY,
    "KNOWN_VSCODE_EXTENSION": PrimaryClassification.KNOWN_DEV_PROXY,
    "CORRELATION_ONLY": PrimaryClassification.UNKNOWN_LOCAL_PROXY,
    "TLS_PATH_MISMATCH": PrimaryClassification.POSSIBLE_MITM_RISK,
}


def to_primary_classification(label: str) -> PrimaryClassification | None:
    """Normalize arbitrary label strings to PrimaryClassification when possible."""
    raw = str(label or "").strip().upper()
    if not raw:
        return None
    try:
        return PrimaryClassification(raw)
    except ValueError:
        pass
    return _ANALYTICS_TO_PRIMARY.get(raw)
