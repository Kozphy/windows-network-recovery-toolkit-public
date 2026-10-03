"""Domain models for the Market Event Intelligence Engine (research-only)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EventCategory(StrEnum):
    """Represent event category data used by the toolkit.

    Attributes:
        MACRO: Field or variant describing m a c r o evidence or state.
        REGULATORY: Field or variant describing r e g u l a t o r y evidence or state.
        TOKEN_UNLOCK: Field or variant describing t o k e n u n l o c k evidence or state.
        PROTOCOL_UPGRADE: Field or variant describing p r o t o c o l u p g r a d e evidence or state.
        GOVERNANCE: Field or variant describing g o v e r n a n c e evidence or state.
        ETF_FLOW: Field or variant describing e t f f l o w evidence or state.
        STABLECOIN_FLOW: Field or variant describing s t a b l e c o i n f l o w evidence or state.
        SECURITY_INCIDENT: Field or variant describing s e c u r i t y i n c i d e n t evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    MACRO = "MACRO"
    REGULATORY = "REGULATORY"
    TOKEN_UNLOCK = "TOKEN_UNLOCK"
    PROTOCOL_UPGRADE = "PROTOCOL_UPGRADE"
    GOVERNANCE = "GOVERNANCE"
    ETF_FLOW = "ETF_FLOW"
    STABLECOIN_FLOW = "STABLECOIN_FLOW"
    SECURITY_INCIDENT = "SECURITY_INCIDENT"
    EXCHANGE_LISTING = "EXCHANGE_LISTING"
    LIQUIDITY_EVENT = "LIQUIDITY_EVENT"


class VolatilityExpectation(StrEnum):
    """Represent volatility expectation data used by the toolkit.

    Attributes:
        LOW: Field or variant describing l o w evidence or state.
        MEDIUM: Field or variant describing m e d i u m evidence or state.
        HIGH: Field or variant describing h i g h evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DirectionBias(StrEnum):
    """Represent direction bias data used by the toolkit.

    Attributes:
        BULLISH: Field or variant describing b u l l i s h evidence or state.
        BEARISH: Field or variant describing b e a r i s h evidence or state.
        NEUTRAL: Field or variant describing n e u t r a l evidence or state.
        UNKNOWN: Field or variant describing u n k n o w n evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    BULLISH = "BULLISH"
    BEARISH = "BEARISH"
    NEUTRAL = "NEUTRAL"
    UNKNOWN = "UNKNOWN"


class ResearchPolicyStatus(StrEnum):
    """Represent research policy status data used by the toolkit.

    Attributes:
        ALLOW_RESEARCH: Field or variant describing a l l o w r e s e a r c h evidence or state.
        PREVIEW_ONLY: Field or variant describing p r e v i e w o n l y evidence or state.
        BLOCK_TRADE_EXECUTION: Field or variant describing b l o c k t r a d e e x e c u t i o n evidence or state.
        BLOCK_LOW_CONFIDENCE: Field or variant describing b l o c k l o w c o n f i d e n c e evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    ALLOW_RESEARCH = "ALLOW_RESEARCH"
    PREVIEW_ONLY = "PREVIEW_ONLY"
    BLOCK_TRADE_EXECUTION = "BLOCK_TRADE_EXECUTION"
    BLOCK_LOW_CONFIDENCE = "BLOCK_LOW_CONFIDENCE"


class MarketEvent(BaseModel):
    """Represent market event data used by the toolkit.

    Attributes:
        event_id: Field or variant describing event id evidence or state.
        title: Field or variant describing title evidence or state.
        category: Field or variant describing category evidence or state.
        timestamp_utc: Field or variant describing timestamp utc evidence or state.
        affected_assets: Field or variant describing affected assets evidence or state.
        expected_volatility: Field or variant describing expected volatility evidence or state.
        direction_bias: Field or variant describing direction bias evidence or state.
        confidence: Field or variant describing confidence evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    event_id: str
    title: str
    category: EventCategory
    timestamp_utc: str
    affected_assets: list[str] = Field(default_factory=list)
    expected_volatility: VolatilityExpectation = VolatilityExpectation.MEDIUM
    direction_bias: DirectionBias = DirectionBias.UNKNOWN
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    source: str = ""
    notes: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetImpact(BaseModel):
    """Represent asset impact data used by the toolkit.

    Attributes:
        asset: Field or variant describing asset evidence or state.
        volatility_contribution: Field or variant describing volatility contribution evidence or state.
        direction_contribution: Field or variant describing direction contribution evidence or state.
        rationale: Field or variant describing rationale evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    asset: str
    volatility_contribution: float = 0.0
    direction_contribution: float = 0.0
    rationale: str = ""


class EventEvidence(BaseModel):
    """Represent event evidence data used by the toolkit.

    Attributes:
        node_id: Field or variant describing node id evidence or state.
        label: Field or variant describing label evidence or state.
        kind: Field or variant describing kind evidence or state.
        detail: Field or variant describing detail evidence or state.
        weight: Field or variant describing weight evidence or state.
        supports_thesis: Field or variant describing supports thesis evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    node_id: str
    label: str
    kind: str
    detail: str = ""
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    supports_thesis: bool | None = None


class SignalScore(BaseModel):
    """Represent signal score data used by the toolkit.

    Attributes:
        event_id: Field or variant describing event id evidence or state.
        volatility_score: Field or variant describing volatility score evidence or state.
        direction_score: Field or variant describing direction score evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        main_drivers: Field or variant describing main drivers evidence or state.
        risk_notes: Field or variant describing risk notes evidence or state.
        asset_impacts: Field or variant describing asset impacts evidence or state.
        policy_status: Field or variant describing policy status evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    event_id: str
    volatility_score: int = Field(ge=0, le=100)
    direction_score: int = Field(ge=-100, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    main_drivers: list[str] = Field(default_factory=list)
    risk_notes: list[str] = Field(default_factory=list)
    asset_impacts: list[AssetImpact] = Field(default_factory=list)
    policy_status: ResearchPolicyStatus = ResearchPolicyStatus.ALLOW_RESEARCH


class TradeThesis(BaseModel):
    """Represent trade thesis data used by the toolkit.

    Attributes:
        event_id: Field or variant describing event id evidence or state.
        headline: Field or variant describing headline evidence or state.
        summary: Field or variant describing summary evidence or state.
        direction_bias: Field or variant describing direction bias evidence or state.
        volatility_expectation: Field or variant describing volatility expectation evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        risk_notes: Field or variant describing risk notes evidence or state.
        disclaimer: Field or variant describing disclaimer evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    event_id: str
    headline: str
    summary: str
    direction_bias: DirectionBias
    volatility_expectation: VolatilityExpectation
    confidence: float
    risk_notes: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "Research draft only — not financial advice. No trade execution is performed or authorized."
    )
    policy_status: ResearchPolicyStatus = ResearchPolicyStatus.ALLOW_RESEARCH


class ThesisOutcome(StrEnum):
    """Represent thesis outcome data used by the toolkit.

    Attributes:
        TRUE: Field or variant describing t r u e evidence or state.
        FALSE: Field or variant describing f a l s e evidence or state.
        PARTIAL: Field or variant describing p a r t i a l evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    TRUE = "true"
    FALSE = "false"
    PARTIAL = "partial"


class PostEventReview(BaseModel):
    """Represent post event review data used by the toolkit.

    Attributes:
        event_id: Field or variant describing event id evidence or state.
        expected_volatility: Field or variant describing expected volatility evidence or state.
        actual_price_change_pct: Field or variant describing actual price change pct evidence or state.
        actual_volume_change_pct: Field or variant describing actual volume change pct evidence or state.
        actual_volatility: Field or variant describing actual volatility evidence or state.
        thesis_correct: Field or variant describing thesis correct evidence or state.
        lessons_learned: Field or variant describing lessons learned evidence or state.
        scoring_adjustment_suggestion: Field or variant describing scoring adjustment suggestion evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    event_id: str
    expected_volatility: VolatilityExpectation
    actual_price_change_pct: float
    actual_volume_change_pct: float
    actual_volatility: VolatilityExpectation
    thesis_correct: ThesisOutcome
    lessons_learned: str = ""
    scoring_adjustment_suggestion: str = ""


class EvidenceTree(BaseModel):
    """Represent evidence tree data used by the toolkit.

    Attributes:
        event_id: Field or variant describing event id evidence or state.
        observation: Field or variant describing observation evidence or state.
        candidate_interpretation: Field or variant describing candidate interpretation evidence or state.
        supporting_evidence: Field or variant describing supporting evidence evidence or state.
        contradicting_evidence: Field or variant describing contradicting evidence evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        final_research_note: Field or variant describing final research note evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    event_id: str
    observation: str
    candidate_interpretation: str
    supporting_evidence: list[EventEvidence] = Field(default_factory=list)
    contradicting_evidence: list[EventEvidence] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    final_research_note: str = ""
