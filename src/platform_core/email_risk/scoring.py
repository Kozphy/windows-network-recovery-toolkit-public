"""Explainable, versioned email risk scoring.

Scoring model (``RULESET_VERSION``):
    1. Additive: sum of evidence weights (one weight per signal).
    2. Correlation adjustments from declarative ``CorrelationRule`` objects
       (``correlation.py``) — each fired rule is itemized in the result.
    3. Level thresholds gated by category diversity: a single evidence family
       (e.g. only authentication failures, or only payment wording) cannot
       exceed MEDIUM; HIGH needs 2+ families and CRITICAL needs 3+.
       ``sender_context`` (free-mail / external / missing auth) and
       ``artifact`` (a QR code merely being present) never count toward
       diversity, so a Gmail sender or a benign ticket QR alone stays LOW.
    4. Level floors: a fired chain rule may raise the level to a minimum
       (e.g. the complete executive → LINE → QR → payment chain is CRITICAL).
       The responsible rule is reported as ``level_floor_rule``.

Side effects:
    None.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from . import correlation as _correlation
from .correlation import (
    DEFAULT_CORRELATION_RULES,
    apply_correlation_rules,
    level_rank,
)
from .models import (
    CorrelationRule,
    EmailRiskConfig,
    EmailRiskEvidence,
    EmailRiskLevel,
    EvidenceSource,
    ScoreAdjustment,
    SignalCategory,
)

SIGNAL_CATEGORY: dict[str, SignalCategory] = {
    "external_sender": SignalCategory.SENDER_CONTEXT,
    "free_mail_sender": SignalCategory.SENDER_CONTEXT,
    "authentication_missing": SignalCategory.SENDER_CONTEXT,
    "from_reply_to_mismatch": SignalCategory.HEADER_AUTHENTICATION,
    "spf_fail": SignalCategory.HEADER_AUTHENTICATION,
    "spf_softfail": SignalCategory.HEADER_AUTHENTICATION,
    "dkim_fail": SignalCategory.HEADER_AUTHENTICATION,
    "dmarc_fail": SignalCategory.HEADER_AUTHENTICATION,
    "suspicious_return_path": SignalCategory.HEADER_AUTHENTICATION,
    "display_name_impersonation": SignalCategory.IDENTITY,
    "executive_impersonation": SignalCategory.IDENTITY,
    "finance_team_impersonation": SignalCategory.IDENTITY,
    "vendor_impersonation": SignalCategory.IDENTITY,
    "lookalike_domain": SignalCategory.IDENTITY,
    "domain_typosquatting": SignalCategory.IDENTITY,
    "urgency": SignalCategory.SOCIAL_ENGINEERING,
    "secrecy_request": SignalCategory.SOCIAL_ENGINEERING,
    "authority_pressure": SignalCategory.SOCIAL_ENGINEERING,
    "credential_request": SignalCategory.CREDENTIAL,
    "external_channel_migration": SignalCategory.CHANNEL_MIGRATION,
    "payment_intent": SignalCategory.PAYMENT,
    "wire_transfer_request": SignalCategory.PAYMENT,
    "bank_account_change": SignalCategory.PAYMENT,
    "invoice_fraud": SignalCategory.PAYMENT,
    "gift_card_request": SignalCategory.PAYMENT,
    "crypto_payment_request": SignalCategory.PAYMENT,
    "qr_code_present": SignalCategory.ARTIFACT,
    "qr_code_scan_request": SignalCategory.QR,
    "qr_code_return_request": SignalCategory.QR,
    "messaging_group_qr_request": SignalCategory.QR,
    "suspicious_url": SignalCategory.URL,
    "suspicious_qr_url": SignalCategory.URL,
}

NON_DIVERSE_CATEGORIES = frozenset({SignalCategory.SENDER_CONTEXT, SignalCategory.ARTIFACT})

DEFAULT_SIGNAL_WEIGHTS: dict[str, float] = {
    "external_sender": 0.05,
    "free_mail_sender": 0.05,
    "authentication_missing": 0.05,
    "from_reply_to_mismatch": 0.15,
    "spf_fail": 0.15,
    "spf_softfail": 0.08,
    "dkim_fail": 0.10,
    "dmarc_fail": 0.20,
    "suspicious_return_path": 0.10,
    "display_name_impersonation": 0.20,
    "executive_impersonation": 0.25,
    "finance_team_impersonation": 0.20,
    "vendor_impersonation": 0.20,
    "lookalike_domain": 0.30,
    "domain_typosquatting": 0.30,
    "urgency": 0.10,
    "secrecy_request": 0.15,
    "authority_pressure": 0.10,
    "credential_request": 0.25,
    "external_channel_migration": 0.20,
    "payment_intent": 0.15,
    "wire_transfer_request": 0.15,
    "bank_account_change": 0.25,
    "invoice_fraud": 0.20,
    "gift_card_request": 0.25,
    "crypto_payment_request": 0.20,
    "qr_code_present": 0.05,
    "qr_code_scan_request": 0.10,
    "qr_code_return_request": 0.20,
    "messaging_group_qr_request": 0.25,
    "suspicious_url": 0.20,
    "suspicious_qr_url": 0.25,
}

QR_HANDOVER_SIGNALS = frozenset(_correlation.QR_HANDOVER_SIGNALS)
IMPERSONATION_SIGNALS = frozenset(_correlation.IMPERSONATION_SIGNALS)
PAYMENT_SIGNALS = frozenset(s for s, c in SIGNAL_CATEGORY.items() if c == SignalCategory.PAYMENT)

THRESHOLD_CRITICAL = 0.80
THRESHOLD_HIGH = 0.55
THRESHOLD_MEDIUM = 0.30


def signal_weight(signal: str, config: EmailRiskConfig) -> float:
    """Return the configured weight for ``signal`` (config override wins)."""
    return float(config.signal_weights.get(signal, DEFAULT_SIGNAL_WEIGHTS[signal]))


def build_evidence(
    signal: str,
    *,
    observed: str,
    source: EvidenceSource,
    detail: str,
    config: EmailRiskConfig,
    weight: float | None = None,
) -> EmailRiskEvidence:
    """Create evidence with ruleset weight and category for ``signal``."""
    return EmailRiskEvidence(
        signal=signal,
        observed=observed,
        weight=signal_weight(signal, config) if weight is None else weight,
        source=source,
        category=SIGNAL_CATEGORY[signal],
        detail=detail,
    )


@dataclass
class ScoreBreakdown:
    """Score, level, and the transparent reasoning behind them."""

    score: float
    level: EmailRiskLevel
    adjustments: list[ScoreAdjustment] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    diverse_categories: int = 0
    fired_rules: list[CorrelationRule] = field(default_factory=list)
    threshold_level: EmailRiskLevel = EmailRiskLevel.UNKNOWN
    level_floor_rule: str = ""


def _threshold_level(score: float, diverse: int) -> EmailRiskLevel:
    if score >= THRESHOLD_CRITICAL and diverse >= 3:
        return EmailRiskLevel.CRITICAL
    if score >= THRESHOLD_HIGH and diverse >= 2:
        return EmailRiskLevel.HIGH
    if score >= THRESHOLD_MEDIUM and diverse >= 1:
        return EmailRiskLevel.MEDIUM
    return EmailRiskLevel.LOW


def score_evidence(
    evidence: list[EmailRiskEvidence],
    *,
    analyzable: bool = True,
    rules: Sequence[CorrelationRule] | None = None,
) -> ScoreBreakdown:
    """Compute score and level from evidence.

    Args:
        evidence: Signal observations (at most one per signal is expected).
        analyzable: False when the message could not be parsed into usable
            content; the level is then ``UNKNOWN`` regardless of evidence.
        rules: Correlation rules to apply (``None`` → built-in defaults;
            an empty sequence disables correlation, e.g. for ablations).
    """
    if not analyzable:
        return ScoreBreakdown(score=0.0, level=EmailRiskLevel.UNKNOWN)

    signals = {e.signal for e in evidence}
    categories = sorted({e.category.value for e in evidence})
    diverse = len({e.category for e in evidence} - NON_DIVERSE_CATEGORIES)
    outcome = apply_correlation_rules(
        signals, DEFAULT_CORRELATION_RULES if rules is None else rules
    )
    raw = sum(e.weight for e in evidence) + sum(a.delta for a in outcome.adjustments)
    score = round(min(1.0, max(0.0, raw)), 3)

    threshold_level = _threshold_level(score, diverse)
    level = threshold_level
    floor_rule = ""
    if outcome.level_floor is not None and level_rank(outcome.level_floor) > level_rank(level):
        level = outcome.level_floor
        floor_rule = outcome.level_floor_rule
    return ScoreBreakdown(
        score=score,
        level=level,
        adjustments=outcome.adjustments,
        categories=categories,
        diverse_categories=diverse,
        fired_rules=list(outcome.fired),
        threshold_level=threshold_level,
        level_floor_rule=floor_rule,
    )
