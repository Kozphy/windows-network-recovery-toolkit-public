"""Merge proxy, TLS, website risk, and proof events into one timeline."""

from __future__ import annotations

from typing import Any

from src.platform_core.timeline.builder import IncidentTimelineBuilder
from src.platform_core.timeline.models import TimelineEntry


def merge_evidence_timeline(
    *,
    incident_id: str,
    proxy_writer: dict[str, Any] | None = None,
    proof_results: dict[str, Any] | None = None,
    tls_proof: dict[str, Any] | None = None,
    website_risk: dict[str, Any] | None = None,
    user_actions: list[dict[str, Any]] | None = None,
    existing_entries: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Merge evidence timeline.

    Args:
        incident_id: incident id supplied by the caller.
        proxy_writer: proxy writer supplied by the caller.
        proof_results: proof results supplied by the caller.
        tls_proof: tls proof supplied by the caller.
        website_risk: website risk supplied by the caller.
        user_actions: user actions supplied by the caller.
        existing_entries: existing entries supplied by the caller.

    Returns:
        The computed `list[dict[str, Any]]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    builder = IncidentTimelineBuilder(incident_id=incident_id)

    if existing_entries:
        for row in existing_entries:
            builder.add_entry(TimelineEntry.model_validate(row))

    if proxy_writer:
        ts = proxy_writer.get("timestamp_utc", "")
        builder.add_entry(
            TimelineEntry(
                timestamp=ts,
                event_type="proxy_registry_observed",
                actor="engine:proxy_writer_attribution",
                object="WinINET",
                after_state=str(proxy_writer.get("registry_state", ""))[:500],
                evidence_refs=[proxy_writer.get("attribution_id", "")],
                confidence_level=str(proxy_writer.get("attribution_confidence", "medium")),
                limitations=proxy_writer.get("limitations", []),
            )
        )
        for w in proxy_writer.get("writer_evidence", []):
            builder.add_entry(
                TimelineEntry(
                    timestamp=w.get("timestamp_utc") or ts,
                    event_type="registry_write_observed",
                    actor=f"telemetry:{w.get('source', 'unknown')}",
                    object=w.get("target_object", ""),
                    after_state=f"{w.get('process_name')} pid={w.get('pid')} details_match={w.get('details_match')}",
                    evidence_refs=[proxy_writer.get("attribution_id", "")],
                    confidence_level="high" if w.get("details_match") else "medium",
                    limitations=[
                        "Registry write event — verify Details field matches expected value."
                    ],
                )
            )

    if proof_results:
        from src.platform_core.proof.models import ProofResult

        try:
            builder.add_proof_result(ProofResult.model_validate(proof_results))
        except Exception:
            builder.add_entry(
                TimelineEntry(
                    timestamp=proof_results.get("timestamp_utc", ""),
                    event_type="network_proof",
                    actor="engine:proof",
                    object=str(proof_results.get("target_url", "")),
                    after_state=str(proof_results.get("outcome", "")),
                    confidence_level=str(proof_results.get("confidence_level", "medium")),
                    limitations=proof_results.get("limitations", []),
                )
            )

    if tls_proof:
        builder.add_entry(
            TimelineEntry(
                timestamp=tls_proof.get("timestamp_utc", ""),
                event_type="tls_proof",
                actor="engine:tls",
                object=tls_proof.get("target_url", ""),
                after_state=f"mismatch={tls_proof.get('certificate_mismatch')} risk={tls_proof.get('mitm_risk_level')}",
                confidence_level="medium",
                limitations=tls_proof.get("limitations", []),
            )
        )

    if website_risk:
        builder.add_entry(
            TimelineEntry(
                timestamp=website_risk.get("timestamp_utc", ""),
                event_type="website_risk_assessed",
                actor="engine:website_risk",
                object=website_risk.get("url", ""),
                after_state=f"{website_risk.get('risk_level')} score={website_risk.get('score')}",
                confidence_level="low",
                limitations=website_risk.get("limitations", []),
            )
        )

    for action in user_actions or []:
        builder.add_entry(
            TimelineEntry(
                timestamp=action.get("timestamp_utc", ""),
                event_type=f"user_action_{action.get('action', 'record')}",
                actor=str(action.get("actor", "user")),
                object=str(action.get("object", "")),
                after_state=str(action.get("detail", ""))[:400],
                confidence_level="very_high",
                limitations=[],
            )
        )

    return builder.build()
