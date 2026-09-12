"""Cross-platform evidence bundle normalization — honest labels, no fake parity."""

from __future__ import annotations

from typing import Any

from src.platform_core.evidence_collection.models import OsFamily, PlatformSupportLevel

WINDOWS_ONLY_SIGNALS = frozenset(
    {
        "proxy_enable",
        "proxy_server",
        "proxy_override",
        "winhttp_proxy_state",
        "wininet_proxy_state",
        "auto_config_url",
    }
)

_DEFAULT_EVIDENCE_LEVEL = "observation"


def normalize_observation_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize one observation dict to the cross-platform evidence schema."""
    signal = str(raw.get("signal_name") or raw.get("name") or "unknown")
    row: dict[str, Any] = {
        "signal_name": signal,
        "value": raw.get("value") if "value" in raw else raw.get("signal_value"),
        "source": str(raw.get("source") or "unknown"),
        "evidence_level": str(raw.get("evidence_level") or _DEFAULT_EVIDENCE_LEVEL),
        "limitations": list(raw.get("limitations") or []),
    }
    for key in ("detail", "error", "status"):
        if key in raw:
            row[key] = raw[key]
    return row


def normalize_evidence_bundle(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a full evidence bundle for APIs, spool rows, and fixture tests."""
    os_family = str(payload.get("os_family") or "unknown")
    level = str(payload.get("platform_support_level") or "NOT_SUPPORTED")
    observations = [
        normalize_observation_row(dict(row))
        for row in payload.get("observations") or []
        if isinstance(row, dict)
    ]
    limitations = list(payload.get("limitations") or [])
    if level in ("PARTIAL", "NOT_SUPPORTED") and not limitations:
        limitations.append("platform_support_limited_explicit_limitations_required")

    normalized: dict[str, Any] = {
        "os_family": os_family,
        "platform_support_level": level,
        "collector_id": str(payload.get("collector_id") or "unknown"),
        "observations": observations,
        "limitations": limitations,
        "live_remediation_supported": bool(payload.get("live_remediation_supported")),
        "collected_at_utc": str(payload.get("collected_at_utc") or ""),
        "epistemic_note": str(
            payload.get("epistemic_note")
            or (
                "Observations are candidate signals only. "
                "Classification is not accusation. Policy ALLOW is not a safety guarantee."
            )
        ),
    }
    return normalized


def assert_honest_platform_labels(
    bundle: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Validate that non-Windows bundles do not claim Windows-only proxy signals."""
    errors: list[str] = []
    os_family: OsFamily = bundle.get("os_family", "unknown")  # type: ignore[assignment]
    level: PlatformSupportLevel = bundle.get("platform_support_level", "NOT_SUPPORTED")  # type: ignore[assignment]
    signals = {row.get("signal_name") for row in bundle.get("observations") or []}

    if os_family == "windows":
        if level != "FULL":
            errors.append("windows_bundle_should_be_FULL_support")
    elif os_family in ("linux", "darwin"):
        if level != "PARTIAL":
            errors.append(f"{os_family}_bundle_should_be_PARTIAL_not_{level}")
        overlap = WINDOWS_ONLY_SIGNALS.intersection(signals)
        if overlap:
            errors.append(f"windows_only_signals_on_{os_family}: {sorted(overlap)}")
        if not bundle.get("limitations"):
            errors.append("non_windows_limitations_required")
    elif level != "NOT_SUPPORTED":
        errors.append("unknown_os_should_be_NOT_SUPPORTED")

    return len(errors) == 0, errors
