"""Immutable stakeholder models — roles and configured identities only.

Stakeholder assignment is not approval. Never invent named persons.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_STAKEHOLDER = "stakeholder_context.v1"


class StakeholderResolutionSource(StrEnum):
    """Represent the stakeholder resolution source enum.

    Variants:
        EXPLICIT_CONFIGURATION: Structured value carried by this enum.
        ASSET_METADATA: Structured value carried by this enum.
        CONTROL_MAPPING: Structured value carried by this enum.
        CLASSIFICATION_MAPPING: Structured value carried by this enum.
        DEFAULT_ROLE_MAPPING: Structured value carried by this enum.
        UNRESOLVED: Structured value carried by this enum.

    Side effects:
        None.
    """

    EXPLICIT_CONFIGURATION = "explicit_configuration"
    ASSET_METADATA = "asset_metadata"
    CONTROL_MAPPING = "control_mapping"
    CLASSIFICATION_MAPPING = "classification_mapping"
    DEFAULT_ROLE_MAPPING = "default_role_mapping"
    UNRESOLVED = "unresolved"


class StakeholderReasonCode(StrEnum):
    """Represent the stakeholder reason code enum.

    Variants:
        STAKEHOLDER_RESOLVED: Structured value carried by this enum.
        OWNER_UNRESOLVED: Structured value carried by this enum.
        APPROVER_REQUIRED: Structured value carried by this enum.
        SECURITY_ESCALATION_REQUIRED: Structured value carried by this enum.
        SEGREGATION_OF_DUTIES_REQUIRED: Structured value carried by this enum.
        EXECUTION_AUTHORITY_MISSING: Structured value carried by this enum.
        INFORMED_ROLE_MAPPED: Structured value carried by this enum.
        AFFECTED_PARTY_MAPPED: Structured value carried by this enum.

    Side effects:
        None.
    """

    STAKEHOLDER_RESOLVED = "STAKEHOLDER_RESOLVED"
    OWNER_UNRESOLVED = "OWNER_UNRESOLVED"
    APPROVER_REQUIRED = "APPROVER_REQUIRED"
    SECURITY_ESCALATION_REQUIRED = "SECURITY_ESCALATION_REQUIRED"
    SEGREGATION_OF_DUTIES_REQUIRED = "SEGREGATION_OF_DUTIES_REQUIRED"
    EXECUTION_AUTHORITY_MISSING = "EXECUTION_AUTHORITY_MISSING"
    INFORMED_ROLE_MAPPED = "INFORMED_ROLE_MAPPED"
    AFFECTED_PARTY_MAPPED = "AFFECTED_PARTY_MAPPED"


class RoleRef(BaseModel):
    """A role or explicitly configured identity — never a guessed person."""

    model_config = ConfigDict(frozen=True)

    role_id: str
    display_name: str
    kind: Literal["role", "configured_identity"] = "role"
    identity: str | None = None
    source: StakeholderResolutionSource = StakeholderResolutionSource.DEFAULT_ROLE_MAPPING
    reason_code: StakeholderReasonCode = StakeholderReasonCode.STAKEHOLDER_RESOLVED
    rationale: str = ""


class EscalationHop(BaseModel):
    """Represent the escalation hop type.

    Key fields:
        order: Structured value carried by this type.
        role: Structured value carried by this type.
        trigger: Structured value carried by this type.

    Side effects:
        None.
    """

    model_config = ConfigDict(frozen=True)

    order: int
    role: RoleRef
    trigger: str = ""


class StakeholderContext(BaseModel):
    """Organizational ownership and authority — separate from technical proof."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_STAKEHOLDER
    case_id: str = ""
    classification: str = ""
    asset_owner: RoleRef | None = None
    control_owner: RoleRef | None = None
    affected_parties: tuple[RoleRef, ...] = ()
    approver_roles: tuple[RoleRef, ...] = ()
    executor_roles: tuple[RoleRef, ...] = ()
    informed_roles: tuple[RoleRef, ...] = ()
    escalation_path: tuple[EscalationHop, ...] = ()
    execution_authority: RoleRef | None = None
    segregation_of_duties_required: bool = True
    resolution_confidence: Literal["unresolved", "role_only", "configured", "partial"] = "role_only"
    unresolved_fields: tuple[str, ...] = ()
    reason_codes: tuple[StakeholderReasonCode, ...] = ()
    limitations: tuple[str, ...] = (
        "Stakeholder assignment is not approval.",
        "Resolver never invents named persons.",
        "Roles come from configuration or deterministic mappings only.",
    )
    inputs_fingerprint: str = ""
    config_refs: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.
        """
        return self.model_dump(mode="json")
