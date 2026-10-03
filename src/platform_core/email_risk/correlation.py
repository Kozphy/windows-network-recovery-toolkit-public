"""Attack-chain correlation: declarative combination rules and attack families.

Module responsibility:
    Signals are not independent evidence. A claimed executive identity plus
    a payment request is far more indicative than either alone, and a request
    to move to LINE, hand over a group QR code, keep it secret, *and* await
    payment instructions is a recognizable multi-stage BEC pattern. This
    module encodes those combinations as explicit, versioned
    ``CorrelationRule`` objects and maps evidence to an ``AttackFamily``.

Correlation model:
    * ``CorrelationRule.requires`` is an AND of OR-groups over signal names.
      When every group has at least one observed signal the rule fires and
      contributes ``delta`` to the score (itemized as a ``ScoreAdjustment``)
      and may impose a ``level_floor`` (e.g. the full executive → channel →
      QR → payment chain is at least CRITICAL).
    * Deltas are bounded (``0 <= delta <= 0.5``) and rules are evaluated in a
      fixed order, so output is deterministic and reproducible.
    * Rule sets are configuration (``EmailRiskConfig.correlation_rules``);
      unknown signal names are rejected rather than silently ignored.

Attack families:
    Each ``FamilyProfile`` lists *anchors* (at least one anchor set must be
    fully present for the family to be selectable) and *stages* (signal
    groups describing a complete instance of the pattern). Family support is
    the summed weight of observed stage signals plus deltas of rules tagged
    with that family. The selected family is the best-supported anchored
    family; ties are broken by a fixed priority. ``confidence`` is an
    uncalibrated support index (see ``family_confidence``) — not a
    probability of maliciousness.

Side effects:
    None. Pure functions over evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .models import (
    AttackChainAssessment,
    AttackFamily,
    CorrelationRule,
    EmailRiskEvidence,
    EmailRiskLevel,
    FamilyScore,
    ScoreAdjustment,
)

IMPERSONATION_SIGNALS: tuple[str, ...] = (
    "display_name_impersonation",
    "domain_typosquatting",
    "executive_impersonation",
    "finance_team_impersonation",
    "lookalike_domain",
    "vendor_impersonation",
)
PAYMENT_SIGNALS: tuple[str, ...] = (
    "bank_account_change",
    "crypto_payment_request",
    "gift_card_request",
    "invoice_fraud",
    "payment_intent",
    "wire_transfer_request",
)
QR_HANDOVER_SIGNALS: tuple[str, ...] = ("messaging_group_qr_request", "qr_code_return_request")
PRESSURE_SIGNALS: tuple[str, ...] = ("secrecy_request", "urgency")
AUTH_FAILURE_SIGNALS: tuple[str, ...] = ("dmarc_fail", "spf_fail")
VENDOR_IDENTITY_SIGNALS: tuple[str, ...] = (
    "domain_typosquatting",
    "lookalike_domain",
    "vendor_impersonation",
)
SENDER_ANOMALY_SIGNALS: tuple[str, ...] = (
    "dmarc_fail",
    "free_mail_sender",
    "from_reply_to_mismatch",
    "spf_fail",
    "suspicious_return_path",
)
URL_RISK_SIGNALS: tuple[str, ...] = ("suspicious_qr_url", "suspicious_url")
MIGRATION = "external_channel_migration"
EXECUTIVE = "executive_impersonation"

DEFAULT_CORRELATION_RULES: tuple[CorrelationRule, ...] = (
    # PR1 rules (IDs, deltas, and signal order preserved).
    CorrelationRule(
        rule_id="CORR_IMPERSONATION_WITH_ACTION_REQUEST",
        requires=[
            list(IMPERSONATION_SIGNALS),
            [MIGRATION, *PAYMENT_SIGNALS, *QR_HANDOVER_SIGNALS],
        ],
        delta=0.15,
        reason="Claimed identity is paired with a channel-move, payment, or QR hand-over request.",
    ),
    CorrelationRule(
        rule_id="CORR_PAYMENT_UNDER_PRESSURE",
        requires=[list(PAYMENT_SIGNALS), list(PRESSURE_SIGNALS)],
        delta=0.10,
        reason="Payment request combined with urgency or secrecy.",
    ),
    CorrelationRule(
        rule_id="CORR_AUTH_FAILURE_WITH_IMPERSONATION",
        requires=[list(AUTH_FAILURE_SIGNALS), list(IMPERSONATION_SIGNALS)],
        delta=0.10,
        reason="Sender authentication failed while an identity is being claimed.",
    ),
    CorrelationRule(
        rule_id="CORR_REPLY_DIVERSION_WITH_PAYMENT",
        requires=[["from_reply_to_mismatch"], list(PAYMENT_SIGNALS)],
        delta=0.10,
        reason="Replies are diverted to another domain on a payment-related message.",
    ),
    # PR3 attack-chain rules.
    CorrelationRule(
        rule_id="EXECUTIVE_PAYMENT_COMBO",
        requires=[[EXECUTIVE], list(PAYMENT_SIGNALS)],
        delta=0.10,
        families=[AttackFamily.BEC_EXECUTIVE_FRAUD],
        reason="An implausible executive identity is attached to a payment request.",
    ),
    CorrelationRule(
        rule_id="CHANNEL_QR_COMBO",
        requires=[[MIGRATION], list(QR_HANDOVER_SIGNALS)],
        delta=0.10,
        families=[AttackFamily.CHANNEL_MIGRATION_SCAM],
        reason="Move to an external messaging app combined with a QR hand-over request "
        "(the QR code grants the sender access to the new channel).",
    ),
    CorrelationRule(
        rule_id="EXECUTIVE_OFF_CHANNEL_SECRECY",
        requires=[[EXECUTIVE], [MIGRATION], ["secrecy_request"]],
        delta=0.05,
        families=[AttackFamily.BEC_EXECUTIVE_FRAUD],
        level_floor=EmailRiskLevel.HIGH,
        reason="Claimed executive moves the conversation off corporate channels and asks "
        "for secrecy — this removes the recipient's normal verification path.",
    ),
    CorrelationRule(
        rule_id="EXECUTIVE_OFF_CHANNEL_PAYMENT",
        requires=[[EXECUTIVE], [MIGRATION], list(PAYMENT_SIGNALS)],
        delta=0.05,
        families=[AttackFamily.BEC_EXECUTIVE_FRAUD],
        level_floor=EmailRiskLevel.HIGH,
        reason="Claimed executive moves the conversation to an external app ahead of a payment.",
    ),
    CorrelationRule(
        rule_id="EXECUTIVE_CHANNEL_QR_PAYMENT_CHAIN",
        requires=[[EXECUTIVE], [MIGRATION], list(QR_HANDOVER_SIGNALS), list(PAYMENT_SIGNALS)],
        delta=0.10,
        families=[AttackFamily.BEC_EXECUTIVE_FRAUD],
        level_floor=EmailRiskLevel.CRITICAL,
        reason="Full executive-fraud chain: executive claim → external messaging app → "
        "QR hand-over → payment.",
    ),
    CorrelationRule(
        rule_id="GIFT_CARD_UNDER_AUTHORITY",
        requires=[["gift_card_request"], [*IMPERSONATION_SIGNALS, "authority_pressure"]],
        delta=0.10,
        families=[AttackFamily.BEC_EXECUTIVE_FRAUD],
        reason="Gift-card purchase requested under a claimed identity or authority.",
    ),
    CorrelationRule(
        rule_id="CHANNEL_MIGRATION_PAYMENT",
        requires=[[MIGRATION], list(PAYMENT_SIGNALS)],
        delta=0.05,
        families=[AttackFamily.CHANNEL_MIGRATION_SCAM],
        reason="Payment discussion is being moved to an external messaging app.",
    ),
    CorrelationRule(
        rule_id="VENDOR_BANK_CHANGE_COMBO",
        requires=[list(VENDOR_IDENTITY_SIGNALS), ["bank_account_change"]],
        delta=0.10,
        families=[AttackFamily.VENDOR_PAYMENT_FRAUD, AttackFamily.ACCOUNT_CHANGE_FRAUD],
        level_floor=EmailRiskLevel.HIGH,
        reason="Beneficiary-account change requested by an imitated or look-alike vendor.",
    ),
    CorrelationRule(
        rule_id="INVOICE_REDIRECTION_CHAIN",
        requires=[["invoice_fraud"], ["bank_account_change", "from_reply_to_mismatch"]],
        delta=0.10,
        families=[AttackFamily.INVOICE_REDIRECTION],
        reason="Invoice payment is redirected to new bank details or a diverted reply path.",
    ),
    CorrelationRule(
        rule_id="ACCOUNT_CHANGE_WITH_SENDER_ANOMALY",
        requires=[["bank_account_change"], list(SENDER_ANOMALY_SIGNALS)],
        delta=0.10,
        families=[AttackFamily.ACCOUNT_CHANGE_FRAUD],
        reason="Bank-detail change arrives with a sender anomaly (auth failure, reply "
        "diversion, or consumer mailbox).",
    ),
    CorrelationRule(
        rule_id="CREDENTIAL_LURE_COMBO",
        requires=[
            ["credential_request"],
            [*URL_RISK_SIGNALS, "lookalike_domain", "domain_typosquatting"],
        ],
        delta=0.15,
        families=[AttackFamily.CREDENTIAL_PHISHING],
        reason="Credential-verification request paired with a suspicious link or look-alike sender.",
    ),
    CorrelationRule(
        rule_id="CREDENTIAL_LURE_UNDER_PRESSURE",
        requires=[["credential_request"], ["urgency", "display_name_impersonation"]],
        delta=0.05,
        families=[AttackFamily.CREDENTIAL_PHISHING],
        reason="Credential request under time pressure or a borrowed display name.",
    ),
    CorrelationRule(
        rule_id="QR_LURE_WITH_SUSPICIOUS_URL",
        requires=[["qr_code_scan_request", "qr_code_present"], ["suspicious_qr_url"]],
        delta=0.10,
        families=[AttackFamily.QR_PHISHING],
        reason="QR code resolves (statically, never visited) to a URL with risk indicators.",
    ),
)


@dataclass(frozen=True)
class FamilyProfile:
    """Anchors (any set fully present) and stages (signal groups) for one family."""

    family: AttackFamily
    anchors: tuple[tuple[str, ...], ...]
    stages: tuple[tuple[str, ...], ...]
    description: str

    @property
    def indicators(self) -> frozenset[str]:
        return frozenset(s for stage in self.stages for s in stage)


FAMILY_PROFILES: tuple[FamilyProfile, ...] = (
    FamilyProfile(
        family=AttackFamily.BEC_EXECUTIVE_FRAUD,
        anchors=((EXECUTIVE,), ("authority_pressure", "gift_card_request")),
        stages=(
            (EXECUTIVE, "display_name_impersonation"),
            ("urgency", "secrecy_request", "authority_pressure"),
            (MIGRATION, *QR_HANDOVER_SIGNALS, "from_reply_to_mismatch"),
            (
                "payment_intent",
                "wire_transfer_request",
                "gift_card_request",
                "crypto_payment_request",
            ),
        ),
        description="Executive / authority impersonation driving an out-of-process action.",
    ),
    FamilyProfile(
        family=AttackFamily.INVOICE_REDIRECTION,
        anchors=(
            ("invoice_fraud", "bank_account_change"),
            ("invoice_fraud", "from_reply_to_mismatch"),
        ),
        stages=(
            ("invoice_fraud",),
            ("bank_account_change", "from_reply_to_mismatch"),
            (*AUTH_FAILURE_SIGNALS, "suspicious_return_path", "urgency", "lookalike_domain"),
        ),
        description="Invoice payment redirected to attacker-controlled details.",
    ),
    FamilyProfile(
        family=AttackFamily.VENDOR_PAYMENT_FRAUD,
        anchors=(
            ("vendor_impersonation",),
            ("lookalike_domain", "invoice_fraud"),
            ("domain_typosquatting", "invoice_fraud"),
            ("lookalike_domain", "bank_account_change"),
            ("domain_typosquatting", "bank_account_change"),
        ),
        stages=(
            VENDOR_IDENTITY_SIGNALS,
            ("bank_account_change", "invoice_fraud", "wire_transfer_request", "payment_intent"),
            ("from_reply_to_mismatch", *AUTH_FAILURE_SIGNALS, "urgency"),
        ),
        description="Imitated supplier requesting payment or payment-detail changes.",
    ),
    FamilyProfile(
        family=AttackFamily.ACCOUNT_CHANGE_FRAUD,
        anchors=(("bank_account_change",),),
        stages=(
            ("bank_account_change",),
            SENDER_ANOMALY_SIGNALS,
            ("urgency", "secrecy_request", "finance_team_impersonation"),
        ),
        description="Request to change beneficiary / payroll bank details.",
    ),
    FamilyProfile(
        family=AttackFamily.CREDENTIAL_PHISHING,
        anchors=(("credential_request",),),
        stages=(
            ("credential_request",),
            (*URL_RISK_SIGNALS, "lookalike_domain", "domain_typosquatting"),
            ("urgency", "display_name_impersonation", *AUTH_FAILURE_SIGNALS),
        ),
        description="Lure to enter or 'verify' account credentials.",
    ),
    FamilyProfile(
        family=AttackFamily.QR_PHISHING,
        anchors=(("suspicious_qr_url",), ("qr_code_scan_request", "credential_request")),
        stages=(
            ("qr_code_present", "qr_code_scan_request"),
            ("suspicious_qr_url",),
            ("credential_request", "urgency", "lookalike_domain", "display_name_impersonation"),
        ),
        description="QR code used to move the victim to a risky URL off the mail gateway's view.",
    ),
    FamilyProfile(
        family=AttackFamily.CHANNEL_MIGRATION_SCAM,
        anchors=((MIGRATION,), ("messaging_group_qr_request",)),
        stages=(
            (MIGRATION,),
            QR_HANDOVER_SIGNALS,
            PRESSURE_SIGNALS,
            PAYMENT_SIGNALS,
        ),
        description="Conversation moved to an external messaging app outside corporate controls.",
    ),
)

FAMILY_PRIORITY: tuple[AttackFamily, ...] = tuple(p.family for p in FAMILY_PROFILES)


class CorrelationConfigError(ValueError):
    """Raised when a configured rule references unknown signals."""


def validate_rules(rules: Iterable[CorrelationRule], known_signals: Iterable[str]) -> None:
    """Reject rules referencing signals the ruleset does not define."""
    known = set(known_signals)
    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise CorrelationConfigError(f"duplicate correlation rule_id: {rule.rule_id}")
        seen.add(rule.rule_id)
        for group in rule.requires:
            if not group:
                raise CorrelationConfigError(f"{rule.rule_id}: empty signal group")
            unknown = sorted(set(group) - known)
            if unknown:
                raise CorrelationConfigError(f"{rule.rule_id}: unknown signals {unknown}")


def active_rules(
    rules: Sequence[CorrelationRule] | None, *, enabled: bool = True
) -> tuple[CorrelationRule, ...]:
    """Return the rule set to apply (``None`` → defaults, disabled → empty)."""
    if not enabled:
        return ()
    return tuple(DEFAULT_CORRELATION_RULES if rules is None else rules)


def _rule_signals(rule: CorrelationRule, signals: set[str]) -> list[str] | None:
    matched: list[str] = []
    for group in rule.requires:
        hits = [s for s in group if s in signals]
        if not hits:
            return None
        matched.extend(s for s in hits if s not in matched)
    return matched


@dataclass(frozen=True)
class CorrelationOutcome:
    """Fired rules, their adjustments, and the strongest level floor (if any)."""

    adjustments: list[ScoreAdjustment]
    fired: list[CorrelationRule]
    level_floor: EmailRiskLevel | None
    level_floor_rule: str


_LEVEL_ORDER = {
    EmailRiskLevel.UNKNOWN: -1,
    EmailRiskLevel.LOW: 0,
    EmailRiskLevel.MEDIUM: 1,
    EmailRiskLevel.HIGH: 2,
    EmailRiskLevel.CRITICAL: 3,
}


def level_rank(level: EmailRiskLevel) -> int:
    """Ordinal rank used for comparisons (UNKNOWN sorts below LOW)."""
    return _LEVEL_ORDER[level]


def apply_correlation_rules(
    signals: set[str], rules: Sequence[CorrelationRule]
) -> CorrelationOutcome:
    """Evaluate ``rules`` against observed ``signals`` in declaration order."""
    adjustments: list[ScoreAdjustment] = []
    fired: list[CorrelationRule] = []
    floor: EmailRiskLevel | None = None
    floor_rule = ""
    for rule in rules:
        matched = _rule_signals(rule, signals)
        if matched is None:
            continue
        fired.append(rule)
        adjustments.append(
            ScoreAdjustment(
                rule_id=rule.rule_id, delta=rule.delta, signals=matched, reason=rule.reason
            )
        )
        if rule.level_floor is not None and (
            floor is None or level_rank(rule.level_floor) > level_rank(floor)
        ):
            floor = rule.level_floor
            floor_rule = rule.rule_id
    return CorrelationOutcome(
        adjustments=adjustments, fired=fired, level_floor=floor, level_floor_rule=floor_rule
    )


def _anchored(profile: FamilyProfile, signals: set[str]) -> bool:
    return any(all(s in signals for s in anchor) for anchor in profile.anchors)


def family_scores(
    evidence: Sequence[EmailRiskEvidence], fired: Sequence[CorrelationRule]
) -> list[FamilyScore]:
    """Score family profiles that are anchored or supported by a fired rule.

    Families touched only by generic indicators (e.g. ``urgency``) are
    omitted. Sorted by (anchored first, support descending, fixed priority).
    """
    signals = {e.signal for e in evidence}
    weights = {e.signal: e.weight for e in evidence}
    out: list[FamilyScore] = []
    for profile in FAMILY_PROFILES:
        indicator_hits = sorted(signals & profile.indicators)
        rule_hits = [r for r in fired if profile.family in r.families]
        anchored = _anchored(profile, signals)
        if not anchored and not rule_hits:
            continue
        support = sum(weights[s] for s in indicator_hits) + sum(r.delta for r in rule_hits)
        out.append(
            FamilyScore(
                family=profile.family,
                support=round(support, 3),
                anchored=anchored,
                signals=indicator_hits,
                rules=[r.rule_id for r in rule_hits],
            )
        )
    priority = {f: i for i, f in enumerate(FAMILY_PRIORITY)}
    out.sort(key=lambda s: (not s.anchored, -s.support, priority[s.family]))
    return out


def _completeness(family: AttackFamily, signals: set[str]) -> float:
    profile = next(p for p in FAMILY_PROFILES if p.family == family)
    satisfied = sum(1 for stage in profile.stages if signals & set(stage))
    return satisfied / len(profile.stages)


def family_confidence(best: FamilyScore, runner_up: FamilyScore | None, signals: set[str]) -> float:
    """Uncalibrated support index in [0, 1] for the selected family.

    ``0.5 * min(1, support) + 0.25 * margin + 0.25 * completeness`` where
    ``margin`` is the relative lead over the next anchored family and
    ``completeness`` is the fraction of the family's stages observed. It
    ranks how well the evidence fits the pattern; it is *not* a calibrated
    probability and must not be read as one.
    """
    support = min(1.0, best.support)
    if runner_up is None or best.support <= 0:
        margin = 1.0
    else:
        margin = max(0.0, (best.support - runner_up.support) / best.support)
    completeness = _completeness(best.family, signals)
    return round(0.5 * support + 0.25 * margin + 0.25 * completeness, 2)


def assess_attack_chain(
    evidence: Sequence[EmailRiskEvidence],
    fired: Sequence[CorrelationRule],
    *,
    level: EmailRiskLevel,
    score: float,
) -> AttackChainAssessment:
    """Select the attack family best supported by ``evidence``.

    Messages ranked LOW / UNKNOWN get ``NONE`` (candidates are still listed
    for transparency). MEDIUM+ messages with no anchored family are labelled
    ``UNKNOWN_SOCIAL_ENGINEERING`` — risk was observed but does not match a
    modeled pattern.
    """
    candidates = family_scores(evidence, fired)
    if level_rank(level) < level_rank(EmailRiskLevel.MEDIUM):
        return AttackChainAssessment(
            family=AttackFamily.NONE,
            candidates=candidates,
            rationale="Risk level below MEDIUM; no attack family asserted.",
        )
    anchored = [c for c in candidates if c.anchored]
    if not anchored:
        return AttackChainAssessment(
            family=AttackFamily.UNKNOWN_SOCIAL_ENGINEERING,
            confidence=round(0.25 * min(1.0, score), 2),
            supporting_signals=sorted({e.signal for e in evidence}),
            candidates=candidates,
            rationale="Risk indicators observed, but no modeled attack family is anchored.",
        )
    best = anchored[0]
    runner_up = anchored[1] if len(anchored) > 1 else None
    signals = {e.signal for e in evidence}
    profile = next(p for p in FAMILY_PROFILES if p.family == best.family)
    return AttackChainAssessment(
        family=best.family,
        confidence=family_confidence(best, runner_up, signals),
        supporting_signals=best.signals,
        supporting_rules=best.rules,
        candidates=candidates,
        rationale=profile.description,
    )
