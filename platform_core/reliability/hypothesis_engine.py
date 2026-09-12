"""Weighted hypothesis ranking — ordinal confidence, not probability."""

from __future__ import annotations

from typing import Any

from .models import NormalizedPlatformEvent, RankedHypothesis

HYPOTHESIS_CATALOG: dict[str, dict[str, Any]] = {
    "known_developer_tool": {
        "category": "known_developer_tool",
        "label": "Known developer tool (Cursor/VS Code/Node dev proxy)",
        "base": 0.25,
        "signals": {
            "localhost_proxy_detected": 0.12,
            "wininet_proxy_enabled": 0.08,
            "node_process": 0.15,
            "ide_parent": 0.10,
            "allowlist_match": 0.12,
        },
    },
    "security_product": {
        "category": "security_product",
        "label": "Security inspection product (Fiddler/Charles/mitmproxy)",
        "base": 0.20,
        "signals": {"security_tool_process": 0.25, "localhost_proxy_detected": 0.10},
    },
    "misconfiguration": {
        "category": "misconfiguration",
        "label": "Misconfiguration or stale localhost proxy registry",
        "base": 0.30,
        "signals": {
            "browser_https_failed": 0.15,
            "wininet_proxy_enabled": 0.10,
            "no_listener": 0.20,
            "proxy_bypass_succeeded": 0.12,
        },
    },
    "potential_malware": {
        "category": "potential_malware",
        "label": "Potential unauthorized proxy (requires proof tier)",
        "base": 0.10,
        "signals": {
            "unresolved_path": 0.15,
            "external_proxy": 0.25,
            "proof_confirmed_unauthorized": 0.30,
        },
    },
}


def _derive_signal_flags(
    events: list[NormalizedPlatformEvent], context: dict[str, Any]
) -> set[str]:
    flags: set[str] = {e.signal_name for e in events}
    for ev in events:
        if ev.evidence_tier == "TIER_3_CAUSAL_PROOF":
            flags.add("proof_confirmed")
        if "node" in str(ev.payload.get("process_name") or "").lower():
            flags.add("node_process")
        if ev.source_kind == "sysmon":
            flags.add("sysmon_registry_write")
    if context.get("allowlist_match"):
        flags.add("allowlist_match")
    if context.get("no_listener"):
        flags.add("no_listener")
    if context.get("external_proxy"):
        flags.add("external_proxy")
    if context.get("security_tool"):
        flags.add("security_tool_process")
    if context.get("unresolved_path"):
        flags.add("unresolved_path")
    return flags


class HypothesisEngine:
    """Rank competing hypotheses from events and context."""

    def rank(
        self,
        events: list[NormalizedPlatformEvent],
        *,
        context: dict[str, Any] | None = None,
    ) -> list[RankedHypothesis]:
        """Provide rank behavior for toolkit workflows.

        Args:
            events: Value supplied by the caller for events.
            context: Value supplied by the caller for context.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return rank_hypotheses(events, context=context)


def rank_hypotheses(
    events: list[NormalizedPlatformEvent],
    *,
    context: dict[str, Any] | None = None,
) -> list[RankedHypothesis]:
    """Return hypotheses sorted by descending ordinal confidence."""
    ctx = context or {}
    flags = _derive_signal_flags(events, ctx)
    ranked: list[RankedHypothesis] = []

    for hid, spec in HYPOTHESIS_CATALOG.items():
        score = float(spec["base"])
        evidence: list[str] = []
        for sig, weight in spec.get("signals", {}).items():
            if sig in flags:
                score += float(weight)
                evidence.append(sig)
        score = min(max(score, 0.0), 0.98)
        ranked.append(
            RankedHypothesis(
                hypothesis_id=hid,
                category=spec["category"],  # type: ignore[arg-type]
                label=spec["label"],
                confidence=round(score, 3),
                supporting_signals=evidence,
            )
        )

    ranked.sort(key=lambda h: h.confidence, reverse=True)

    adjusted: list[RankedHypothesis] = []
    for h in ranked:
        if h.category == "potential_malware" and "proof_confirmed" not in flags:
            adjusted.append(
                RankedHypothesis(
                    hypothesis_id=h.hypothesis_id,
                    category=h.category,
                    label=h.label,
                    confidence=min(h.confidence, 0.35),
                    supporting_signals=h.supporting_signals,
                    rejected_reason="Elevated malware hypothesis requires proof-tier evidence.",
                )
            )
        else:
            adjusted.append(h)
    adjusted.sort(key=lambda x: x.confidence, reverse=True)
    return adjusted
