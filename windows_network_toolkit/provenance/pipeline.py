"""Orchestrate domain-provenance: normalize → collect → score → policy → audit.

Module responsibility:
    End-to-end read-only pipeline for ``domain-provenance``.

System placement:
    Called from CLI ``cmd_domain_provenance`` and package ``__init__``.

Key invariants:
    * Fixture mode is deterministic and network-free for RDAP/GeoIP.
    * ``online=True`` required for RDAP.org / country.is.
    * IPs redacted by default for console and audit.
    * Does not mutate Windows network state or call remediation modules.

Side effects:
    Optional soft-append to ``.audit/domain-provenance.jsonl``.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.provenance.collectors import (
    collect_live_signals,
    signals_from_fixture,
)
from windows_network_toolkit.provenance.models import (
    PROVENANCE_LIMITATIONS,
    SCHEMA_VERSION,
    DomainProvenanceResult,
)
from windows_network_toolkit.provenance.normalize import normalize_target
from windows_network_toolkit.provenance.policy import evaluate_provenance_policy
from windows_network_toolkit.provenance.redact import redact_structure
from windows_network_toolkit.provenance.scoring import score_provenance

HttpGet = Callable[[str, float], dict[str, Any]]


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_domain_provenance(
    target: str,
    *,
    fixture: dict[str, Any] | None = None,
    online: bool = False,
    redact_ips: bool = True,
    append_audit: bool = True,
    http_get: HttpGet | None = None,
    resolve_a: Callable[[str], list[str]] | None = None,
    audit_log_name: str = "domain-provenance.jsonl",
) -> dict[str, Any]:
    """Run the domain-provenance pipeline.

    Args:
        target: Domain or URL to assess.
        fixture: Optional inject dict (or full fixture with nested keys).
        online: When True (and no fixture), call RDAP.org / country.is.
        redact_ips: When True (default), mask IPs in output and audit.
        append_audit: When True, soft-append audit JSONL.
        http_get: Injectable HTTP JSON getter (tests / online).
        resolve_a: Injectable DNS A resolver (tests).
        audit_log_name: Audit filename under ``.audit/``.

    Returns:
        Governance-enveloped dict suitable for CLI JSON output.

    Side effects:
        Optional audit append; optional outbound HTTPS when ``online`` and no fixture.

    Audit Notes:
        Policy always requires human review; never treat result as ownership proof
        or remediation authorization.
    """
    host = normalize_target(target)
    mode = "fixture" if fixture is not None else ("online" if online else "offline")

    if fixture is not None:
        # Allow either bare evidence dict or wrapped ``{"domain_provenance": {...}}``.
        body = fixture.get("domain_provenance") if isinstance(fixture, dict) else None
        evidence = body if isinstance(body, dict) else fixture
        fixture_target = str(evidence.get("target") or target)
        host = normalize_target(fixture_target) or host
        signals = signals_from_fixture(evidence, host)
    else:
        signals = collect_live_signals(
            host,
            online=online,
            http_get=http_get,
            resolve_a=resolve_a,
        )

    score = score_provenance(signals)
    policy = evaluate_provenance_policy(score)
    limitations = list(PROVENANCE_LIMITATIONS)
    if mode == "offline":
        limitations.append(
            "Offline mode: RDAP.org and country.is were not queried; pass --online for adapters."
        )
    if not host:
        limitations.append("Target could not be normalized to a hostname.")

    result = DomainProvenanceResult(
        schema_version=SCHEMA_VERSION,
        assessment_id=str(uuid.uuid4()),
        timestamp_utc=_utc_now(),
        target_raw=target,
        target_normalized=host,
        mode=mode,
        score=score,
        policy=policy,
        limitations=limitations,
        redaction={"ips_redacted": redact_ips, "default": True},
    )

    payload = result.to_dict()
    if redact_ips:
        payload = redact_structure(payload)
        payload["redaction"] = {"ips_redacted": True, "default": True}

    payload = attach_governance_envelope(
        payload,
        policy_outcome=policy.decision.value,
        dry_run=True,
    )
    # Reinforce epistemic boundaries for provenance specifically.
    gov = payload.setdefault("governance", {})
    if isinstance(gov, dict):
        gov["execution_authority"] = "human_required"
        gov["classification_is_accusation"] = False

    if append_audit:
        audit_row = {
            "event": "domain_provenance",
            "timestamp_utc": payload.get("timestamp_utc"),
            "assessment_id": payload.get("assessment_id"),
            "target_normalized": payload.get("target_normalized"),
            "operator_country": payload.get("operator_country"),
            "confidence": payload.get("confidence"),
            "confidence_band": payload.get("confidence_band"),
            "policy": payload.get("policy"),
            "mode": payload.get("mode"),
            "redaction": payload.get("redaction"),
            "limitations": payload.get("limitations"),
            "score": payload.get("score"),
        }
        if redact_ips:
            audit_row = redact_structure(audit_row)
        ok, err = append_audit_dict(audit_row, log_name=audit_log_name)
        payload["audit_appended"] = ok
        payload["audit_error"] = err
    else:
        payload["audit_appended"] = False
        payload["audit_error"] = None

    return payload
