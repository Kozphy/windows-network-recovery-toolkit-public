"""Deterministic StakeholderResolver — roles/config only; never invents persons."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from src.platform_core.stakeholder.escalation import build_escalation_path
from src.platform_core.stakeholder.models import (
    RoleRef,
    StakeholderContext,
    StakeholderReasonCode,
    StakeholderResolutionSource,
)
from src.platform_core.stakeholder.registry import (
    CONTROL_OWNER_MAP,
    SECURITY_ESCALATION_CLASSIFICATIONS,
    load_explicit_config,
    map_for_classification,
    role_display,
)


def _fingerprint(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _role_from_config(
    *,
    field: str,
    role_id: str | None,
    identities: dict[str, str],
    source: StakeholderResolutionSource,
    reason: StakeholderReasonCode,
    rationale: str,
) -> RoleRef | None:
    if not role_id:
        return None
    identity = identities.get(role_id) or identities.get(field)
    kind = "configured_identity" if identity else "role"
    src = (
        StakeholderResolutionSource.EXPLICIT_CONFIGURATION
        if identity or source == StakeholderResolutionSource.EXPLICIT_CONFIGURATION
        else source
    )
    return RoleRef(
        role_id=role_id,
        display_name=role_display(role_id),
        kind=kind,  # type: ignore[arg-type]
        identity=identity,
        source=src,
        reason_code=reason,
        rationale=rationale,
    )


class StakeholderResolver:
    """Resolve organizational roles from evidence/classification/policy/config."""

    def resolve(
        self,
        *,
        case_id: str = "",
        classification: str = "",
        evidence_summary: dict[str, Any] | None = None,
        proof_status: str = "",
        policy_outcome: str = "",
        policy_requires_approval: bool = False,
        control_ids: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> StakeholderContext:
        """Resolve the requested value.

        Args:
            case_id: case id supplied by the caller.
            classification: classification supplied by the caller.
            evidence_summary: evidence summary supplied by the caller.
            proof_status: proof status supplied by the caller.
            policy_outcome: policy outcome supplied by the caller.
            policy_requires_approval: policy requires approval supplied by the caller.
            control_ids: control ids supplied by the caller.
            config: config supplied by the caller.

        Returns:
            The computed `StakeholderContext` value.

        Side effects:
            None.
        """
        evidence_summary = evidence_summary or {}
        cfg = load_explicit_config(config)
        identities = {
            str(k): str(v)
            for k, v in (cfg.get("identities") or {}).items()
            if isinstance(k, str) and isinstance(v, str) and v.strip()
        }
        class_map = map_for_classification(classification)
        reasons: list[StakeholderReasonCode] = []
        unresolved: list[str] = []

        def pick(field: str, default_role: str) -> tuple[str, StakeholderResolutionSource, str]:
            if field in cfg and cfg[field]:
                return (
                    str(cfg[field]),
                    StakeholderResolutionSource.EXPLICIT_CONFIGURATION,
                    "explicit config",
                )
            asset_meta = evidence_summary.get("asset") or {}
            if isinstance(asset_meta, dict) and asset_meta.get(field):
                return (
                    str(asset_meta[field]),
                    StakeholderResolutionSource.ASSET_METADATA,
                    "asset metadata",
                )
            if field == "control_owner" and control_ids:
                for cid in control_ids:
                    if cid in CONTROL_OWNER_MAP:
                        return (
                            CONTROL_OWNER_MAP[cid],
                            StakeholderResolutionSource.CONTROL_MAPPING,
                            f"control {cid}",
                        )
            if classification and class_map.get(field):
                return (
                    class_map[field],
                    StakeholderResolutionSource.CLASSIFICATION_MAPPING,
                    f"classification {classification}",
                )
            return (
                default_role,
                StakeholderResolutionSource.DEFAULT_ROLE_MAPPING,
                "default role map",
            )

        ao_id, ao_src, ao_why = pick("asset_owner", class_map["asset_owner"])
        co_id, co_src, co_why = pick("control_owner", class_map["control_owner"])
        ap_id, ap_src, ap_why = pick("approver", class_map["approver"])
        ex_id, ex_src, ex_why = pick("executor", class_map["executor"])
        inf_id, inf_src, inf_why = pick("informed", class_map["informed"])
        esc_id, esc_src, esc_why = pick("escalation", class_map["escalation"])

        asset_owner = _role_from_config(
            field="asset_owner",
            role_id=ao_id,
            identities=identities,
            source=ao_src,
            reason=StakeholderReasonCode.STAKEHOLDER_RESOLVED,
            rationale=ao_why,
        )
        control_owner = _role_from_config(
            field="control_owner",
            role_id=co_id,
            identities=identities,
            source=co_src,
            reason=StakeholderReasonCode.STAKEHOLDER_RESOLVED,
            rationale=co_why,
        )
        approver = _role_from_config(
            field="approver",
            role_id=ap_id,
            identities=identities,
            source=ap_src,
            reason=StakeholderReasonCode.APPROVER_REQUIRED,
            rationale=ap_why,
        )
        executor = _role_from_config(
            field="executor",
            role_id=ex_id,
            identities=identities,
            source=ex_src,
            reason=StakeholderReasonCode.STAKEHOLDER_RESOLVED,
            rationale=ex_why,
        )
        informed = _role_from_config(
            field="informed",
            role_id=inf_id,
            identities=identities,
            source=inf_src,
            reason=StakeholderReasonCode.INFORMED_ROLE_MAPPED,
            rationale=inf_why,
        )
        escalation = _role_from_config(
            field="escalation",
            role_id=esc_id,
            identities=identities,
            source=esc_src,
            reason=StakeholderReasonCode.STAKEHOLDER_RESOLVED,
            rationale=esc_why,
        )

        if asset_owner is None:
            unresolved.append("asset_owner")
            reasons.append(StakeholderReasonCode.OWNER_UNRESOLVED)
        else:
            reasons.append(StakeholderReasonCode.STAKEHOLDER_RESOLVED)

        needs_approval = bool(policy_requires_approval) or str(policy_outcome).upper() in {
            "REQUIRE_HUMAN_APPROVAL",
            "REQUIRE_TYPED_CONFIRMATION",
            "REQUIRE_CONFIRMATION",
            "ROLLBACK_REQUIRED",
            "PREVIEW_ONLY",
            "PREVIEW",
            "ALLOW_PREVIEW",
            "CORRELATION_ONLY_ALERT",
        }
        approvers: list[RoleRef] = []
        if needs_approval:
            reasons.append(StakeholderReasonCode.APPROVER_REQUIRED)
            if approver is None:
                unresolved.append("approver")
            else:
                approvers.append(approver)

        security_required = str(classification).upper() in SECURITY_ESCALATION_CLASSIFICATIONS
        if security_required:
            reasons.append(StakeholderReasonCode.SECURITY_ESCALATION_REQUIRED)

        sod = bool(cfg.get("segregation_of_duties_required", True))
        if sod and approver and executor and approver.role_id == executor.role_id:
            reasons.append(StakeholderReasonCode.SEGREGATION_OF_DUTIES_REQUIRED)
            # Prefer splitting: executor stays; approver escalates to lead if same
            if escalation and escalation.role_id != executor.role_id:
                approvers = [
                    RoleRef(
                        role_id=escalation.role_id,
                        display_name=escalation.display_name,
                        kind=escalation.kind,
                        identity=escalation.identity,
                        source=StakeholderResolutionSource.DEFAULT_ROLE_MAPPING,
                        reason_code=StakeholderReasonCode.SEGREGATION_OF_DUTIES_REQUIRED,
                        rationale="Approver must differ from executor (SoD).",
                    )
                ]

        execution_authority = None
        if executor and (not needs_approval or approvers):
            execution_authority = executor
        else:
            reasons.append(StakeholderReasonCode.EXECUTION_AUTHORITY_MISSING)
            unresolved.append("execution_authority")

        affected: list[RoleRef] = []
        if asset_owner:
            affected.append(
                RoleRef(
                    role_id=asset_owner.role_id,
                    display_name=asset_owner.display_name,
                    kind=asset_owner.kind,
                    identity=asset_owner.identity,
                    source=asset_owner.source,
                    reason_code=StakeholderReasonCode.AFFECTED_PARTY_MAPPED,
                    rationale="Asset owner is an affected party.",
                )
            )

        esc_path = build_escalation_path(
            classification=classification,
            primary_escalation=escalation
            or RoleRef(
                role_id="it_operations_lead",
                display_name=role_display("it_operations_lead"),
                source=StakeholderResolutionSource.DEFAULT_ROLE_MAPPING,
                reason_code=StakeholderReasonCode.STAKEHOLDER_RESOLVED,
                rationale="fallback escalation",
            ),
            security_required=security_required,
        )

        if (
            unresolved
            and StakeholderReasonCode.OWNER_UNRESOLVED not in reasons
            and "asset_owner" in unresolved
        ):
            reasons.append(StakeholderReasonCode.OWNER_UNRESOLVED)

        confidence: str = "role_only"
        if identities:
            confidence = "configured"
        if unresolved:
            confidence = "partial" if (asset_owner or control_owner) else "unresolved"
        if not classification and not cfg:
            confidence = "unresolved"
            if "asset_owner" not in unresolved:
                unresolved.append("asset_owner")

        fp = _fingerprint(
            {
                "case_id": case_id,
                "classification": classification,
                "policy_outcome": policy_outcome,
                "policy_requires_approval": needs_approval,
                "proof_status": proof_status,
                "control_ids": control_ids or [],
                "config": cfg,
            }
        )

        return StakeholderContext(
            case_id=case_id,
            classification=classification,
            asset_owner=asset_owner,
            control_owner=control_owner,
            affected_parties=tuple(affected),
            approver_roles=tuple(approvers),
            executor_roles=tuple([executor] if executor else []),
            informed_roles=tuple([informed] if informed else []),
            escalation_path=esc_path,
            execution_authority=execution_authority,
            segregation_of_duties_required=sod,
            resolution_confidence=confidence,  # type: ignore[arg-type]
            unresolved_fields=tuple(dict.fromkeys(unresolved)),
            reason_codes=tuple(dict.fromkeys(reasons)),
            inputs_fingerprint=fp,
            config_refs={"has_explicit_config": bool(cfg), "identity_count": len(identities)},
        )


def resolve_stakeholders(**kwargs: Any) -> StakeholderContext:
    """Resolve stakeholders.

    Args:
        **kwargs: kwargs supplied by the caller.

    Returns:
        The computed `StakeholderContext` value.

    Side effects:
        None.
    """
    return StakeholderResolver().resolve(**kwargs)
