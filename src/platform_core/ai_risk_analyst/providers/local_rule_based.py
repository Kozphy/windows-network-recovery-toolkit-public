"""Deterministic rule-based risk analyst — default when no API key is configured."""

from __future__ import annotations

from src.platform_core.ai_risk_analyst.explanation_guardrails import sanitize_explanation_text
from src.platform_core.ai_risk_analyst.models import (
    AIRecommendation,
    AnalystEvidenceBundle,
    RiskHypothesis,
)
from src.platform_core.ai_risk_analyst.providers.base import AnalystProvider

_SCENARIO_TABLE: dict[str, dict[str, str]] = {
    "NO_PROXY": {
        "summary": "No WinINET proxy misconfiguration observed.",
        "hypothesis": "Endpoint proxy path appears nominal; browser failures likely have another cause.",
        "action": "If symptoms persist, run diagnose --proof and review DNS/TLS/application layers.",
        "risk": "low",
        "confidence": "high",
    },
    "DEAD_PROXY_CONFIG": {
        "summary": "WinINET references a localhost proxy port with no active listener.",
        "hypothesis": "Browser HTTPS failures are consistent with a stale or dead proxy configuration.",
        "action": "Preview proxy-disable with typed confirmation; verify with proxy-status after change.",
        "risk": "medium",
        "confidence": "high",
    },
    "LOCAL_PROXY_ENABLED": {
        "summary": "Localhost proxy is enabled and a listener is present.",
        "hypothesis": "A local development or VPN proxy is intercepting browser traffic.",
        "action": "Identify process owner (proxy-owner) and confirm intent before changing settings.",
        "risk": "medium",
        "confidence": "medium",
    },
    "KNOWN_DEV_PROXY": {
        "summary": "Local proxy listener matches a known development-tool pattern.",
        "hypothesis": "Traffic is likely routed through a dev tool proxy (e.g. Node-based helper).",
        "action": "Confirm with developer; no malicious classification implied. Review only if unintended.",
        "risk": "low",
        "confidence": "medium",
    },
    "SUSPICIOUS_LOCAL_PROXY": {
        "summary": "Unknown localhost proxy listener without strong attribution.",
        "hypothesis": "Unattributed local proxy requires human review before remediation.",
        "action": "Run proxy-writer-attribution and proxy-investigate; escalate to security reviewer.",
        "risk": "high",
        "confidence": "low",
    },
    "POSSIBLE_MITM_RISK": {
        "summary": "Signals suggest possible certificate or proxy-path inconsistency.",
        "hypothesis": "MITM risk cannot be confirmed without TLS path contrast proof.",
        "action": "Collect tls-proof (read-only) and compare direct vs proxied certificate metadata.",
        "risk": "high",
        "confidence": "very_low",
    },
    "REVERTER_SUSPECTED": {
        "summary": "Proxy settings appear to flip or revert after remediation attempts.",
        "hypothesis": "An active reverter process or scheduled job may be re-enabling proxy settings.",
        "action": "Run proxy-watch and proxy-investigate; attribute registry writer before remediation.",
        "risk": "high",
        "confidence": "medium",
    },
}


class LocalRuleBasedAnalyst(AnalystProvider):
    """Represent the local rule based analyst type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    name = "local_rule_based"

    def analyze(self, bundle: AnalystEvidenceBundle) -> AIRecommendation:
        """Return analyze.

        Args:
            bundle: bundle supplied by the caller.

        Returns:
            The computed `AIRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        primary = self._resolve_primary(bundle)
        if primary == "LOCAL_PROXY_ENABLED" and self._is_dev_proxy(bundle):
            primary = "KNOWN_DEV_PROXY"

        scenario = _SCENARIO_TABLE.get(primary, _SCENARIO_TABLE["SUSPICIOUS_LOCAL_PROXY"])
        evidence_used = self._collect_evidence_refs(bundle)
        missing = self._default_missing(bundle, primary)

        hypotheses = [
            RiskHypothesis(
                hypothesis_id=f"hyp-primary-{bundle.incident_id}",
                title=scenario["hypothesis"],
                explanation=scenario["summary"],
                confidence=scenario["confidence"],  # type: ignore[arg-type]
                supporting_evidence=evidence_used,
                missing_evidence=missing,
                alternative_explanations=self._alternatives(primary),
            )
        ]

        return AIRecommendation(
            provider=self.name,
            incident_summary=sanitize_explanation_text(scenario["summary"]),
            likely_hypothesis=sanitize_explanation_text(scenario["hypothesis"]),
            missing_evidence=missing,
            risk_level=scenario["risk"],  # type: ignore[arg-type]
            confidence_level=scenario["confidence"],  # type: ignore[arg-type]
            recommended_action=sanitize_explanation_text(scenario["action"]),
            human_review_notes="Rule-based analyst output; human review required for suspicious classes.",
            evidence_used=evidence_used,
            assumptions=[
                "Classification labels are triage signals, not accusations.",
                "Listener correlation does not prove registry writer identity.",
            ],
            uncertainty="Ordinal confidence only; not a statistical probability.",
            alternative_explanations=self._alternatives(primary),
            hypotheses=hypotheses,
            limitations=[
                "This module does not execute remediation.",
                "Observation is not proof; correlation is not causation.",
            ],
            governance_notes=[
                "Policy permission is not a safety guarantee.",
                "AI suggestions are explainable, reviewable, and auditable.",
            ],
        )

    def _resolve_primary(self, bundle: AnalystEvidenceBundle) -> str:
        if bundle.classification:
            return str(bundle.classification.get("primary_classification", "")).upper()
        if bundle.proxy_status:
            return str(bundle.proxy_status.get("classification", "")).upper()
        return "NO_PROXY"

    def _is_dev_proxy(self, bundle: AnalystEvidenceBundle) -> bool:
        proc = (bundle.listener_info or {}).get("process") or {}
        name = str(proc.get("name", proc) if isinstance(proc, dict) else proc).lower()
        return any(h in name for h in ("node", "cursor", "code", "vscode"))

    def _collect_evidence_refs(self, bundle: AnalystEvidenceBundle) -> list[str]:
        refs: list[str] = []
        if bundle.proxy_status:
            refs.append("proxy_status")
        if bundle.listener_info:
            refs.append("listener_info")
        if bundle.timeline_events:
            refs.append("timeline_events")
        if bundle.tls_proof:
            refs.append("tls_proof")
        if bundle.website_risk:
            refs.append("website_risk")
        if bundle.audit_log_entries:
            refs.append("audit_log_entries")
        if bundle.classification:
            refs.append("classification")
        if bundle.proof:
            refs.append("proof")
        return refs

    def _default_missing(self, bundle: AnalystEvidenceBundle, primary: str) -> list[str]:
        missing: list[str] = []
        if primary in {"SUSPICIOUS_LOCAL_PROXY", "UNKNOWN_LOCAL_PROXY", "REVERTER_SUSPECTED"}:
            if not bundle.audit_log_entries:
                missing.append("registry_writer_attribution")
        if primary == "POSSIBLE_MITM_RISK" and not bundle.tls_proof:
            missing.append("tls_proof")
        if bundle.listener_info and not bundle.listener_info.get("listener_found"):
            missing.append("verified_listener")
        return missing

    def _alternatives(self, primary: str) -> list[str]:
        common = [
            "Misconfigured VPN or corporate proxy policy.",
            "Stale user-session proxy after dev tool exit.",
            "Browser extension or PAC file not captured in this bundle.",
        ]
        if primary == "DEAD_PROXY_CONFIG":
            return ["Dev proxy crashed leaving registry behind.", *common]
        if primary == "REVERTER_SUSPECTED":
            return ["Scheduled task re-enabling proxy.", "MDM/GPO policy override.", *common]
        return common
