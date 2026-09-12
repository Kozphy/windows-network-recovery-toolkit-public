"""Domain adapters for federated Decision Intelligence Platform."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.decision_engine.scoring import (
    CandidateDecision,
    EvidenceItem,
    ScoredDecision,
    score_candidate,
)
from src.platform_core.decision_intelligence.models import (
    DecisionDomain,
    DomainRecommendation,
    EvidenceTrace,
    FederatedEvidenceInput,
    ScoreExplain,
)


def _confidence_display(score: float) -> str:
    return f"ordinal {score:.2f} (domain score input, not probability)"


def _to_explain(scored: ScoredDecision) -> ScoreExplain:
    b = scored.breakdown
    return ScoreExplain(
        benefit=scored.benefit,
        risk=scored.risk,
        confidence=scored.confidence,
        final_score=scored.final_score,
        benefit_components=b.benefit_components,
        risk_components=b.risk_components,
        confidence_components=b.confidence_components,
        formulas=b.formulas,
    )


class DecisionDomainAdapter(ABC):
    """Represent the decision domain adapter type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    @property
    @abstractmethod
    def domain(self) -> DecisionDomain:
        """Return domain.

        Returns:
            The computed `DecisionDomain` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ...

    @abstractmethod
    def build_candidates(self, evidence: FederatedEvidenceInput) -> list[CandidateDecision]:
        """Build candidates.

        Args:
            evidence: evidence supplied by the caller.

        Returns:
            The computed `list[CandidateDecision]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ...

    def score_best(
        self, evidence: FederatedEvidenceInput, shared: list[EvidenceItem]
    ) -> tuple[ScoredDecision, list[ScoredDecision]]:
        """Score best.

        Args:
            evidence: evidence supplied by the caller.
            shared: shared supplied by the caller.

        Returns:
            The computed `tuple[ScoredDecision, list[ScoredDecision]]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        candidates = self.build_candidates(evidence)
        scored = [score_candidate(shared, c) for c in candidates]
        scored.sort(key=lambda s: s.final_score, reverse=True)
        return scored[0], scored

    @abstractmethod
    def to_recommendation(
        self,
        top: ScoredDecision,
        all_scored: list[ScoredDecision],
        evidence: FederatedEvidenceInput,
        shared: list[EvidenceItem],
    ) -> DomainRecommendation:
        """Return to recommendation.

        Args:
            top: top supplied by the caller.
            all_scored: all scored supplied by the caller.
            evidence: evidence supplied by the caller.
            shared: shared supplied by the caller.

        Returns:
            The computed `DomainRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ...


class ITOperationsAdapter(DecisionDomainAdapter):
    """Represent the itoperations adapter type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    @property
    def domain(self) -> DecisionDomain:
        """Return domain.

        Returns:
            The computed `DecisionDomain` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DecisionDomain.IT_OPERATIONS

    def build_candidates(self, evidence: FederatedEvidenceInput) -> list[CandidateDecision]:
        """Build candidates.

        Args:
            evidence: evidence supplied by the caller.

        Returns:
            The computed `list[CandidateDecision]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return [
            CandidateDecision(
                decision_id="it_preview_disable_wininet",
                label="Preview disable WinINET proxy",
                base_benefit=60.0,
                base_risk=20.0,
                evidence_relevance={"proxy_enabled": 1.0, "listener_absent": 0.9},
            ),
            CandidateDecision(
                decision_id="it_observe_only",
                label="Observe proxy state",
                base_benefit=30.0,
                base_risk=5.0,
                evidence_relevance={"proxy_enabled": 0.5},
            ),
        ]

    def to_recommendation(
        self, top, all_scored, evidence, shared
    ) -> DomainRecommendation:
        """Return to recommendation.

        Args:
            top: top supplied by the caller.
            all_scored: all scored supplied by the caller.
            evidence: evidence supplied by the caller.
            shared: shared supplied by the caller.

        Returns:
            The computed `DomainRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        trace = [
            EvidenceTrace(evidence_id=e.evidence_id, signal=e.label, role="supporting")
            for e in shared
            if e.supports_decision
        ][:4]
        posture: str = "PREVIEW" if top.decision_id == "it_preview_disable_wininet" else "OBSERVE"
        return DomainRecommendation(
            domain=self.domain,
            recommendation_id=top.decision_id,
            title=top.decision,
            recommendation=(
                "After structured proof, preview DISABLE_WININET_PROXY with typed confirmation."
                if posture == "PREVIEW"
                else top.recommendation
            ),
            policy_posture=posture,  # type: ignore[arg-type]
            confidence=top.confidence,
            confidence_display=_confidence_display(top.confidence),
            evidence_trace=trace,
            limitations=list(evidence.limitations) or ["Does not prove malware or MITM."],
            explain=_to_explain(top),
            ranked_alternatives=[s.decision for s in all_scored[1:3]],
        )


class SecurityAdapter(DecisionDomainAdapter):
    """Represent the security adapter type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    @property
    def domain(self) -> DecisionDomain:
        """Return domain.

        Returns:
            The computed `DecisionDomain` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DecisionDomain.SECURITY

    def build_candidates(self, evidence: FederatedEvidenceInput) -> list[CandidateDecision]:
        """Build candidates.

        Args:
            evidence: evidence supplied by the caller.

        Returns:
            The computed `list[CandidateDecision]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return [
            CandidateDecision(
                decision_id="sec_monitor_process",
                label="Monitor process and collect writer proof",
                base_benefit=45.0,
                base_risk=10.0,
                evidence_relevance={"listener_absent": 0.7, "proxy_enabled": 0.6},
            ),
            CandidateDecision(
                decision_id="sec_escalate_mitm",
                label="Escalate TLS/MITM review",
                base_benefit=35.0,
                base_risk=25.0,
                evidence_relevance={"tls_mismatch": 1.0},
            ),
        ]

    def to_recommendation(self, top, all_scored, evidence, shared) -> DomainRecommendation:
        """Return to recommendation.

        Args:
            top: top supplied by the caller.
            all_scored: all scored supplied by the caller.
            evidence: evidence supplied by the caller.
            shared: shared supplied by the caller.

        Returns:
            The computed `DomainRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DomainRecommendation(
            domain=self.domain,
            recommendation_id=top.decision_id,
            title="Monitor process and collect writer proof",
            recommendation=(
                "Monitor for reverter respawn; collect Sysmon E13 registry writer telemetry "
                "before containment decisions."
            ),
            policy_posture="OBSERVE",
            confidence=top.confidence,
            confidence_display=_confidence_display(top.confidence),
            evidence_trace=[
                EvidenceTrace(evidence_id=e.evidence_id, signal=e.label, role="supporting")
                for e in shared[:3]
            ],
            limitations=["Listener correlation is not registry-writer proof."],
            explain=_to_explain(top),
            ranked_alternatives=[s.decision for s in all_scored[1:2]],
        )


class RiskAdapter(DecisionDomainAdapter):
    """Represent the risk adapter type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    @property
    def domain(self) -> DecisionDomain:
        """Return domain.

        Returns:
            The computed `DecisionDomain` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DecisionDomain.RISK

    def build_candidates(self, evidence: FederatedEvidenceInput) -> list[CandidateDecision]:
        """Build candidates.

        Args:
            evidence: evidence supplied by the caller.

        Returns:
            The computed `list[CandidateDecision]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return [
            CandidateDecision(
                decision_id="risk_collect_evidence",
                label="Collect additional evidence",
                base_benefit=40.0,
                base_risk=35.0,
                evidence_relevance={"missing_writer": 1.0, "proxy_enabled": 0.5},
            ),
            CandidateDecision(
                decision_id="risk_accept_with_limits",
                label="Accept hypothesis with documented limitations",
                base_benefit=35.0,
                base_risk=30.0,
            ),
        ]

    def to_recommendation(self, top, all_scored, evidence, shared) -> DomainRecommendation:
        """Return to recommendation.

        Args:
            top: top supplied by the caller.
            all_scored: all scored supplied by the caller.
            evidence: evidence supplied by the caller.
            shared: shared supplied by the caller.

        Returns:
            The computed `DomainRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        missing = ["registry_writer_telemetry", "proof_path_contrast"]
        return DomainRecommendation(
            domain=self.domain,
            recommendation_id=top.decision_id,
            title="Collect additional evidence",
            recommendation=(
                "Defer strong causation claims until writer telemetry or structured path proof is complete."
            ),
            policy_posture="DEFER",
            confidence=top.confidence,
            confidence_display=_confidence_display(top.confidence),
            evidence_trace=[
                EvidenceTrace(
                    evidence_id="missing-writer",
                    signal="registry_writer_telemetry",
                    role="missing",
                )
            ],
            missing_evidence=missing,
            limitations=["Confidence is not certainty; observation is not proof."],
            explain=_to_explain(top),
            ranked_alternatives=[s.decision for s in all_scored[1:2]],
        )


class BusinessAdapter(DecisionDomainAdapter):
    """Represent the business adapter type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    @property
    def domain(self) -> DecisionDomain:
        """Return domain.

        Returns:
            The computed `DecisionDomain` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DecisionDomain.BUSINESS

    def build_candidates(self, evidence: FederatedEvidenceInput) -> list[CandidateDecision]:
        """Build candidates.

        Args:
            evidence: evidence supplied by the caller.

        Returns:
            The computed `list[CandidateDecision]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return [
            CandidateDecision(
                decision_id="biz_minimize_downtime",
                label="Minimize user downtime — surgical fix",
                base_benefit=65.0,
                base_risk=15.0,
                evidence_relevance={"browser_fail": 1.0, "ping_ok": 0.8},
            ),
            CandidateDecision(
                decision_id="biz_broad_reset",
                label="Broad network reset (high disruption)",
                base_benefit=30.0,
                base_risk=55.0,
            ),
        ]

    def to_recommendation(self, top, all_scored, evidence, shared) -> DomainRecommendation:
        """Return to recommendation.

        Args:
            top: top supplied by the caller.
            all_scored: all scored supplied by the caller.
            evidence: evidence supplied by the caller.
            shared: shared supplied by the caller.

        Returns:
            The computed `DomainRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DomainRecommendation(
            domain=self.domain,
            recommendation_id=top.decision_id,
            title="Minimize user downtime",
            recommendation=(
                "Prefer surgical WinINET disable over adapter reset, firewall reset, or broad network changes."
            ),
            policy_posture="PREVIEW",
            confidence=top.confidence,
            confidence_display=_confidence_display(top.confidence),
            evidence_trace=[
                EvidenceTrace(evidence_id=e.evidence_id, signal=e.label, role="supporting")
                for e in shared[:2]
            ],
            limitations=["Business priority does not override security or compliance gates."],
            explain=_to_explain(top),
            ranked_alternatives=[s.decision for s in all_scored[1:2]],
        )


class ComplianceAdapter(DecisionDomainAdapter):
    """Represent the compliance adapter type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    @property
    def domain(self) -> DecisionDomain:
        """Return domain.

        Returns:
            The computed `DecisionDomain` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DecisionDomain.COMPLIANCE

    def build_candidates(self, evidence: FederatedEvidenceInput) -> list[CandidateDecision]:
        """Build candidates.

        Args:
            evidence: evidence supplied by the caller.

        Returns:
            The computed `list[CandidateDecision]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return [
            CandidateDecision(
                decision_id="cmp_audit_and_limitations",
                label="Audit log and document limitations",
                base_benefit=55.0,
                base_risk=5.0,
            ),
        ]

    def to_recommendation(self, top, all_scored, evidence, shared) -> DomainRecommendation:
        """Return to recommendation.

        Args:
            top: top supplied by the caller.
            all_scored: all scored supplied by the caller.
            evidence: evidence supplied by the caller.
            shared: shared supplied by the caller.

        Returns:
            The computed `DomainRecommendation` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return DomainRecommendation(
            domain=self.domain,
            recommendation_id=top.decision_id,
            title="Audit log and document limitations",
            recommendation=(
                "Append audit JSONL, retain evidence chain, document limitations in incident record."
            ),
            policy_posture="ALLOW",
            confidence=top.confidence,
            confidence_display=_confidence_display(top.confidence),
            evidence_trace=[
                EvidenceTrace(evidence_id=e.evidence_id, signal=e.label, role="supporting")
                for e in shared
            ],
            limitations=["Audit completeness does not imply regulatory certification."],
            explain=_to_explain(top),
            ranked_alternatives=[],
        )


ADAPTERS: tuple[DecisionDomainAdapter, ...] = (
    ITOperationsAdapter(),
    SecurityAdapter(),
    RiskAdapter(),
    BusinessAdapter(),
    ComplianceAdapter(),
)
