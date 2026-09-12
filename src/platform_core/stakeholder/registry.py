"""Deterministic stakeholder role registry — classification and control mappings."""

from __future__ import annotations

from typing import Any

# Classification → default organizational roles (no personal identities).
CLASSIFICATION_ROLE_MAP: dict[str, dict[str, str]] = {
    "DEAD_PROXY_CONFIG": {
        "asset_owner": "endpoint_owner",
        "control_owner": "endpoint_reliability_control_owner",
        "approver": "it_operations_approver",
        "executor": "desktop_support_executor",
        "informed": "service_desk",
        "escalation": "it_operations_lead",
    },
    "KNOWN_DEV_PROXY": {
        "asset_owner": "endpoint_owner",
        "control_owner": "developer_tooling_control_owner",
        "approver": "it_operations_approver",
        "executor": "endpoint_owner",
        "informed": "developer_experience",
        "escalation": "it_operations_lead",
    },
    "LOCAL_PROXY_ACTIVE": {
        "asset_owner": "endpoint_owner",
        "control_owner": "endpoint_reliability_control_owner",
        "approver": "it_operations_approver",
        "executor": "desktop_support_executor",
        "informed": "service_desk",
        "escalation": "it_operations_lead",
    },
    "UNKNOWN_LOCAL_PROXY": {
        "asset_owner": "endpoint_owner",
        "control_owner": "security_control_owner",
        "approver": "security_approver",
        "executor": "security_operations_executor",
        "informed": "it_operations_lead",
        "escalation": "security_incident_manager",
    },
    "POSSIBLE_MITM_RISK": {
        "asset_owner": "endpoint_owner",
        "control_owner": "security_control_owner",
        "approver": "security_approver",
        "executor": "security_operations_executor",
        "informed": "ciso_office",
        "escalation": "security_incident_manager",
    },
    "WININET_WINHTTP_MISMATCH": {
        "asset_owner": "endpoint_owner",
        "control_owner": "endpoint_reliability_control_owner",
        "approver": "it_operations_approver",
        "executor": "desktop_support_executor",
        "informed": "service_desk",
        "escalation": "it_operations_lead",
    },
    "OS_NETWORK_OK_BROWSER_PROFILE_FAIL": {
        "asset_owner": "endpoint_owner",
        "control_owner": "endpoint_reliability_control_owner",
        "approver": "it_operations_approver",
        "executor": "desktop_support_executor",
        "informed": "service_desk",
        "escalation": "it_operations_lead",
    },
}

DEFAULT_ROLE_MAP: dict[str, str] = {
    "asset_owner": "endpoint_owner",
    "control_owner": "endpoint_reliability_control_owner",
    "approver": "it_operations_approver",
    "executor": "desktop_support_executor",
    "informed": "service_desk",
    "escalation": "it_operations_lead",
}

ROLE_DISPLAY: dict[str, str] = {
    "endpoint_owner": "Endpoint Owner",
    "endpoint_reliability_control_owner": "Endpoint Reliability Control Owner",
    "developer_tooling_control_owner": "Developer Tooling Control Owner",
    "security_control_owner": "Security Control Owner",
    "it_operations_approver": "IT Operations Approver",
    "security_approver": "Security Approver",
    "desktop_support_executor": "Desktop Support Executor",
    "security_operations_executor": "Security Operations Executor",
    "service_desk": "Service Desk (Informed)",
    "developer_experience": "Developer Experience (Informed)",
    "it_operations_lead": "IT Operations Lead",
    "security_incident_manager": "Security Incident Manager",
    "ciso_office": "CISO Office (Informed)",
}

# Classifications that require security-path escalation (organizational, not technical fact).
SECURITY_ESCALATION_CLASSIFICATIONS: frozenset[str] = frozenset(
    {
        "UNKNOWN_LOCAL_PROXY",
        "POSSIBLE_MITM_RISK",
        "SUSPICIOUS_PROXY",
    }
)

# Control-id → control owner role (optional override).
CONTROL_OWNER_MAP: dict[str, str] = {
    "CTRL-PROXY-001": "endpoint_reliability_control_owner",
    "CTRL-PROXY-002": "security_control_owner",
    "CTRL-TLS-001": "security_control_owner",
}


def role_display(role_id: str) -> str:
    """Return role display.

    Args:
        role_id: role id supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.
    """
    return ROLE_DISPLAY.get(role_id, role_id.replace("_", " ").title())


def map_for_classification(classification: str) -> dict[str, str]:
    """Map for classification.

    Args:
        classification: classification supplied by the caller.

    Returns:
        The computed `dict[str, str]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    key = str(classification or "").strip().upper()
    return dict(CLASSIFICATION_ROLE_MAP.get(key) or DEFAULT_ROLE_MAP)


def load_explicit_config(config: dict[str, Any] | None) -> dict[str, Any]:
    """Return a safe copy of optional local stakeholder config."""
    if not config:
        return {}
    allowed = {
        "asset_owner",
        "control_owner",
        "approver",
        "executor",
        "informed",
        "escalation",
        "identities",
        "segregation_of_duties_required",
    }
    return {k: v for k, v in config.items() if k in allowed}
