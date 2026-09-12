"""Canonical evidence levels — ordinal ranking, not calibrated probability."""

from __future__ import annotations

from typing import Any, Literal

EvidenceLevel = Literal[
    "OBSERVED_ONLY",
    "CORRELATED",
    "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION",
]

EVIDENCE_LEVEL_ORDER: tuple[EvidenceLevel, ...] = (
    "OBSERVED_ONLY",
    "CORRELATED",
    "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION",
)

_RANK = {level: i for i, level in enumerate(EVIDENCE_LEVEL_ORDER)}


def evidence_rank(level: str | EvidenceLevel) -> int:
    """Provide evidence rank behavior for toolkit workflows.

    Args:
        level: Value supplied by the caller for level.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return _RANK.get(str(level).upper(), -1)  # type: ignore[arg-type]


def can_upgrade_to_final_causation(
    *,
    has_writer_telemetry: bool,
    has_network_impact_proof: bool = False,
    has_port_owner_match: bool = False,
) -> bool:
    """Evaluate the can upgrade to final causation condition.

    Args:
        has_writer_telemetry: Value supplied by the caller for has writer telemetry.
        has_network_impact_proof: Value supplied by the caller for has network impact proof.
        has_port_owner_match: Value supplied by the caller for has port owner match.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return has_writer_telemetry and (has_network_impact_proof or has_port_owner_match)


def can_upgrade_evidence(
    current: str | EvidenceLevel,
    proposed: str | EvidenceLevel,
    *,
    has_writer_telemetry: bool = False,
    has_network_impact_proof: bool = False,
    has_port_owner_match: bool = False,
    has_listener_correlation_only: bool = False,
) -> bool:
    """Return whether *proposed* level is allowed given proof inputs."""
    cur, prop = str(current).upper(), str(proposed).upper()
    if evidence_rank(prop) <= evidence_rank(cur):
        return prop == cur
    if has_listener_correlation_only and evidence_rank(prop) > evidence_rank("CORRELATED"):
        return False
    if evidence_rank(prop) >= evidence_rank("PROVEN_REGISTRY_WRITER") and not has_writer_telemetry:
        return False
    if (
        evidence_rank(prop) >= evidence_rank("PROVEN_NETWORK_IMPACT")
        and not has_network_impact_proof
    ):
        return False
    if prop == "FINAL_CAUSATION":
        return can_upgrade_to_final_causation(
            has_writer_telemetry=has_writer_telemetry,
            has_network_impact_proof=has_network_impact_proof,
            has_port_owner_match=has_port_owner_match,
        )
    return True


def resolve_evidence_level(inputs: dict[str, Any]) -> EvidenceLevel:
    """Derive canonical level from normalized proof inputs."""
    registry_changed = bool(inputs.get("registry_changed") or inputs.get("proxy_enable_changed"))
    listener = bool(inputs.get("listener_correlation") or inputs.get("port_owner_match"))
    writer = bool(
        inputs.get("sysmon_event_13")
        or inputs.get("procmon_regset")
        or inputs.get("etw_registry_write")
        or inputs.get("writer_telemetry")
    )
    network = bool(
        inputs.get("browser_path_failed")
        or inputs.get("https_path_failed")
        or inputs.get("network_impact_proof")
    )
    port_owner = bool(inputs.get("port_owner_match"))

    if writer and can_upgrade_to_final_causation(
        has_writer_telemetry=writer,
        has_network_impact_proof=network,
        has_port_owner_match=port_owner,
    ):
        return "FINAL_CAUSATION"
    if network and writer:
        return "PROVEN_NETWORK_IMPACT"
    if writer:
        return "PROVEN_REGISTRY_WRITER"
    if listener or inputs.get("heuristic_process_match"):
        return "CORRELATED"
    if registry_changed or inputs.get("proxy_state_observed"):
        return "OBSERVED_ONLY"
    return "OBSERVED_ONLY"


def evidence_limitations(level: EvidenceLevel) -> list[str]:
    """Provide evidence limitations behavior for toolkit workflows.

    Args:
        level: Value supplied by the caller for level.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    base = ["Confidence is ordinal ranking, not calibrated probability."]
    notes = {
        "OBSERVED_ONLY": "Registry/proxy state observed; writer not identified.",
        "CORRELATED": "Listener/process correlation only — not registry writer proof.",
        "PROVEN_REGISTRY_WRITER": "Writer proof requires Sysmon/Procmon/ETW-class telemetry.",
        "PROVEN_NETWORK_IMPACT": "Browser-path impact correlated with proxy state.",
        "FINAL_CAUSATION": "Highest toolkit tier — not antivirus or autonomous containment.",
    }
    return base + [notes.get(level, "")]
