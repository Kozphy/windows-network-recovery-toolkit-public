"""Trade thesis draft generator (research narrative, not execution)."""

from __future__ import annotations

from .models import DirectionBias, MarketEvent, SignalScore, TradeThesis, VolatilityExpectation


def _volatility_label(score: int) -> VolatilityExpectation:
    if score >= 65:
        return VolatilityExpectation.HIGH
    if score >= 35:
        return VolatilityExpectation.MEDIUM
    return VolatilityExpectation.LOW


def _direction_from_score(score: int) -> DirectionBias:
    if score >= 20:
        return DirectionBias.BULLISH
    if score <= -20:
        return DirectionBias.BEARISH
    if score == 0:
        return DirectionBias.NEUTRAL
    return DirectionBias.UNKNOWN


def build_trade_thesis(event: MarketEvent, signal: SignalScore) -> TradeThesis:
    """Build trade thesis.

    Args:
        event: Evidence or domain record being processed.
        signal: The signal value supplied by the caller.

    Returns:
        The TradeThesis result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    vol = _volatility_label(signal.volatility_score)
    direction = _direction_from_score(signal.direction_score)
    drivers = (
        "; ".join(signal.main_drivers) if signal.main_drivers else "No dominant drivers flagged."
    )
    summary = (
        f"For {event.event_id} ({event.category.value}), research draft suggests "
        f"{direction.value} bias with {vol.value} volatility sensitivity. "
        f"Confidence={signal.confidence:.2f}. Drivers: {drivers}"
    )
    return TradeThesis(
        event_id=event.event_id,
        headline=f"Research thesis: {event.title}",
        summary=summary,
        direction_bias=direction,
        volatility_expectation=vol,
        confidence=signal.confidence,
        risk_notes=list(signal.risk_notes),
        policy_status=signal.policy_status,
    )
