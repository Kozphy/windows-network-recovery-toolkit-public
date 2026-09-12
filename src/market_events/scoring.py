"""Deterministic signal scoring for market catalyst events."""

from __future__ import annotations

from .models import (
    AssetImpact,
    DirectionBias,
    EventCategory,
    MarketEvent,
    SignalScore,
    VolatilityExpectation,
)
from .policy import apply_policy_to_score, evaluate_research_policy

_MACRO_ASSETS = frozenset({"BTC", "ETH", "SPX", "DXY", "US10Y"})
_VOL_BASE = {VolatilityExpectation.LOW: 20, VolatilityExpectation.MEDIUM: 45, VolatilityExpectation.HIGH: 70}
_DIR_BASE = {
    DirectionBias.BULLISH: 35,
    DirectionBias.BEARISH: -35,
    DirectionBias.NEUTRAL: 0,
    DirectionBias.UNKNOWN: 0,
}


def _clamp_int(value: float, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(round(value))))


def score_event(event: MarketEvent, *, request_execution: bool = False) -> SignalScore:
    """Score event.
    
    Args:
        event: Evidence or domain record being processed.
        request_execution: The request execution value supplied by the caller.
    
    Returns:
        The SignalScore result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    volatility = float(_VOL_BASE.get(event.expected_volatility, 45))
    direction = float(_DIR_BASE.get(event.direction_bias, 0))
    confidence = float(event.confidence)
    drivers: list[str] = []
    risks: list[str] = []
    impacts: list[AssetImpact] = []

    assets = {a.upper() for a in event.affected_assets}
    if event.category == EventCategory.MACRO and assets & _MACRO_ASSETS:
        volatility += 15
        drivers.append("High-impact macro event affecting BTC/ETH or macro proxies")
        for asset in sorted(assets & _MACRO_ASSETS):
            impacts.append(
                AssetImpact(
                    asset=asset,
                    volatility_contribution=12.0,
                    direction_contribution=0.0,
                    rationale="Macro catalyst cross-asset volatility channel",
                )
            )

    if event.category == EventCategory.TOKEN_UNLOCK:
        supply_pct = float(event.metadata.get("supply_pct_unlocked", 0) or 0)
        if supply_pct >= 5.0:
            direction -= min(40.0, supply_pct * 3.0)
            volatility += min(25.0, supply_pct * 2.0)
            drivers.append(f"Token unlock with {supply_pct:.1f}% supply entering float")
            risks.append("Large unlock events often increase near-term sell pressure")
            for asset in event.affected_assets:
                impacts.append(
                    AssetImpact(
                        asset=asset,
                        volatility_contribution=min(25.0, supply_pct * 2.0),
                        direction_contribution=-min(40.0, supply_pct * 3.0),
                        rationale="Supply expansion catalyst",
                    )
                )

    if event.category == EventCategory.PROTOCOL_UPGRADE:
        if event.metadata.get("confirmed_date"):
            confidence = min(1.0, confidence + 0.15)
            drivers.append("Protocol upgrade date confirmed — schedule confidence increased")
        volatility += 10
        direction += 10

    if event.category == EventCategory.REGULATORY:
        direction -= 20
        volatility += 15
        drivers.append("Regulatory enforcement or policy headline")
        risks.append("Regulatory downside tail risk — observation is not proof of market reaction")

    if event.category == EventCategory.ETF_FLOW:
        direction += 25
        volatility += 10
        drivers.append("ETF flow catalyst — bullish bias channel")

    if event.category == EventCategory.SECURITY_INCIDENT:
        direction -= 30
        volatility += 25
        drivers.append("Security incident — downside and volatility risk")
        risks.append("Exploit/hack headlines may gap price; verify on-chain evidence")

    if event.category == EventCategory.STABLECOIN_FLOW:
        volatility += 8
        drivers.append("Stablecoin flow event — liquidity and peg-stress monitor")

    if event.category == EventCategory.EXCHANGE_LISTING:
        direction += 15
        volatility += 12
        drivers.append("Exchange listing — attention and liquidity catalyst")

    if event.category == EventCategory.LIQUIDITY_EVENT:
        volatility += 18
        drivers.append("Liquidity event — slippage and volatility sensitivity")

    if event.category == EventCategory.GOVERNANCE:
        volatility += 6
        drivers.append("Governance vote or parameter change")

    if not event.source.strip():
        risks.append("No attributable source on calendar row")

    policy = evaluate_research_policy(event, request_execution=request_execution)
    score = SignalScore(
        event_id=event.event_id,
        volatility_score=_clamp_int(volatility, 0, 100),
        direction_score=_clamp_int(direction, -100, 100),
        confidence=round(min(1.0, max(0.0, confidence)), 4),
        main_drivers=drivers,
        risk_notes=risks,
        asset_impacts=impacts,
    )
    return apply_policy_to_score(score, policy)
