"""Advisory policy gate for email risk results.

Module responsibility:
    Turn an assessment (risk level, signals, attack family) into advisory
    decisions — ALLOW, WARN, HUMAN_VERIFY, QUARANTINE_RECOMMENDED,
    BLOCK_ACTION — plus human-performed recommended actions and out-of-band
    verification guidance.

Key invariants:
    * Advisory only. The gate never sends, moves, deletes, or quarantines
      mail, disables accounts, contacts anyone, or moves money.
      ``BLOCK_ACTION`` means "recommend that a person not perform the
      requested action" (payment, bank change, QR hand-over, credential
      entry). ``automated_actions_taken`` is always empty.
    * Multiple policies may match; all are reported (``matched_policies``)
      and their decisions are merged, deduplicated, and ordered by severity.
      ``WARN`` is subsumed by any stronger decision; ``ALLOW`` is only
      returned when no policy matched.
    * Verification guidance never points at contact data supplied by the
      message itself (phone numbers, new messaging IDs, QR codes, Reply-To).
    * Policies are configuration (``EmailRiskConfig.policy_rules``);
      unknown signal names are rejected.

Side effects:
    None.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from .correlation import (
    PAYMENT_SIGNALS,
    QR_HANDOVER_SIGNALS,
    URL_RISK_SIGNALS,
    level_rank,
)
from .models import (
    AttackFamily,
    EmailRiskLevel,
    MatchedPolicy,
    PolicyCondition,
    PolicyDecision,
    PolicyGateResult,
    PolicyRule,
    VerificationGuidance,
)

DECISION_SEVERITY: dict[PolicyDecision, int] = {
    PolicyDecision.ALLOW: 0,
    PolicyDecision.WARN: 1,
    PolicyDecision.HUMAN_VERIFY: 2,
    PolicyDecision.QUARANTINE_RECOMMENDED: 3,
    PolicyDecision.BLOCK_ACTION: 4,
}

VERIFICATION_INSTRUCTION = (
    "Verify the request using an independently known corporate channel, such as a "
    "previously stored company phone number, official Teams/Slack account, or in-person "
    "confirmation."
)

DO_NOT_TRUST_BASE: tuple[str, ...] = (
    "Phone numbers that appear only in this message",
    "New LINE / WhatsApp / Telegram / WeChat IDs or group invites supplied by the sender",
    "QR codes contained in, or requested by, this message",
    "Reply-To or new email addresses introduced by this message",
)

DECISION_ACTIONS: dict[PolicyDecision, str] = {
    PolicyDecision.BLOCK_ACTION: (
        "Do not perform the requested action (payment, bank-detail change, gift-card "
        "purchase, QR-code hand-over, or credential entry) until it has been verified "
        "out-of-band. The toolkit has not blocked or changed anything."
    ),
    PolicyDecision.QUARANTINE_RECOMMENDED: (
        "Report the message to your security team for review; quarantine, if warranted, "
        "is performed by your mail platform's administrators. The toolkit has not moved "
        "or deleted the message."
    ),
    PolicyDecision.HUMAN_VERIFY: VERIFICATION_INSTRUCTION,
    PolicyDecision.WARN: (
        "Treat the message with caution; do not act on its links, QR codes, attachments, "
        "or contact details without independent confirmation."
    ),
    PolicyDecision.ALLOW: (
        "No policy action recommended. A LOW result is not proof the message is safe."
    ),
}

SIGNAL_ACTIONS: tuple[tuple[str, str], ...] = (
    (
        "bank_account_change",
        "Confirm any bank-detail change with the payee using contact details already on "
        "file (e.g. vendor master data), never details from this message.",
    ),
    (
        "gift_card_request",
        "Legitimate organizations rarely request gift cards by email or chat; confirm with "
        "the requester in person before buying anything.",
    ),
    (
        "messaging_group_qr_request",
        "Do not create or join messaging groups, or send their QR codes, at the request of "
        "an email sender — the QR code grants the sender access to the group.",
    ),
    (
        "qr_code_return_request",
        "Do not photograph or return QR codes to the sender; they can grant account or "
        "group access.",
    ),
    (
        "credential_request",
        "Do not enter credentials from a link in this message; sign in only via a "
        "bookmarked or typed address.",
    ),
)

_PAYMENT = list(PAYMENT_SIGNALS)
_QR_HANDOVER = list(QR_HANDOVER_SIGNALS)

DEFAULT_POLICY_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        policy_id="P1_HIGH_RISK_PAYMENT",
        description="risk >= HIGH AND payment intent",
        when=PolicyCondition(min_level=EmailRiskLevel.HIGH, signal_groups=[_PAYMENT]),
        decisions=[PolicyDecision.HUMAN_VERIFY],
        rationale="High-risk message requests a payment-related action.",
    ),
    PolicyRule(
        policy_id="P2_EXECUTIVE_CHANNEL_MIGRATION",
        description="executive_impersonation AND external_channel_migration",
        when=PolicyCondition(
            signal_groups=[["executive_impersonation"], ["external_channel_migration"]]
        ),
        decisions=[PolicyDecision.QUARANTINE_RECOMMENDED],
        rationale="Claimed executive is moving the conversation off corporate channels.",
    ),
    PolicyRule(
        policy_id="P3_QR_HANDOVER_WITH_PAYMENT",
        description="QR return / group-QR request AND payment intent",
        when=PolicyCondition(signal_groups=[_QR_HANDOVER, _PAYMENT]),
        decisions=[PolicyDecision.BLOCK_ACTION],
        rationale="QR hand-over combined with a payment request.",
    ),
    PolicyRule(
        policy_id="P4_BANK_ACCOUNT_CHANGE",
        description="bank_account_change (any risk level)",
        when=PolicyCondition(signal_groups=[["bank_account_change"]]),
        decisions=[PolicyDecision.HUMAN_VERIFY],
        rationale="Bank-detail changes always require independent verification.",
    ),
    PolicyRule(
        policy_id="P5_CRITICAL",
        description="risk == CRITICAL",
        when=PolicyCondition(min_level=EmailRiskLevel.CRITICAL),
        decisions=[PolicyDecision.BLOCK_ACTION, PolicyDecision.HUMAN_VERIFY],
        rationale="Critical-risk message.",
    ),
    PolicyRule(
        policy_id="B1_MEDIUM_WARN",
        description="risk >= MEDIUM",
        when=PolicyCondition(min_level=EmailRiskLevel.MEDIUM),
        decisions=[PolicyDecision.WARN],
        rationale="Risk indicators observed.",
    ),
    PolicyRule(
        policy_id="B2_HIGH_QUARANTINE",
        description="risk >= HIGH",
        when=PolicyCondition(min_level=EmailRiskLevel.HIGH),
        decisions=[PolicyDecision.QUARANTINE_RECOMMENDED],
        rationale="High-risk message should be reviewed by the security team.",
    ),
    PolicyRule(
        policy_id="B3_QR_HANDOVER_VERIFY",
        description="QR hand-over request AND risk >= MEDIUM",
        when=PolicyCondition(min_level=EmailRiskLevel.MEDIUM, signal_groups=[_QR_HANDOVER]),
        decisions=[PolicyDecision.HUMAN_VERIFY],
        rationale="Returning a QR code can grant the sender account or group access.",
    ),
    PolicyRule(
        policy_id="B4_GIFT_CARD_VERIFY",
        description="gift_card_request AND risk >= MEDIUM",
        when=PolicyCondition(
            min_level=EmailRiskLevel.MEDIUM, signal_groups=[["gift_card_request"]]
        ),
        decisions=[PolicyDecision.HUMAN_VERIFY],
        rationale="Gift-card requests are a common low-friction fraud pattern.",
    ),
    PolicyRule(
        policy_id="B5_CREDENTIAL_LURE",
        description="credential_request AND risky link / look-alike AND risk >= MEDIUM",
        when=PolicyCondition(
            min_level=EmailRiskLevel.MEDIUM,
            signal_groups=[
                ["credential_request"],
                [*URL_RISK_SIGNALS, "lookalike_domain", "domain_typosquatting"],
            ],
        ),
        decisions=[PolicyDecision.QUARANTINE_RECOMMENDED],
        rationale="Credential lure with a risky link or look-alike sender.",
    ),
    PolicyRule(
        policy_id="B6_SUSPICIOUS_QR_URL",
        description="suspicious_qr_url AND risk >= MEDIUM",
        when=PolicyCondition(
            min_level=EmailRiskLevel.MEDIUM, signal_groups=[["suspicious_qr_url"]]
        ),
        decisions=[PolicyDecision.QUARANTINE_RECOMMENDED],
        rationale="QR code decodes to a URL with static risk indicators.",
    ),
    PolicyRule(
        policy_id="B7_UNANALYZABLE",
        description="risk == UNKNOWN",
        when=PolicyCondition(levels=[EmailRiskLevel.UNKNOWN]),
        decisions=[PolicyDecision.WARN],
        rationale="Message could not be analyzed; absence of findings is not assurance.",
    ),
)


class PolicyConfigError(ValueError):
    """Raised when a configured policy is empty or references unknown signals."""


def validate_policy_rules(rules: Iterable[PolicyRule], known_signals: Iterable[str]) -> None:
    """Reject duplicate IDs, empty conditions, and unknown signal names."""
    known = set(known_signals)
    seen: set[str] = set()
    for rule in rules:
        if rule.policy_id in seen:
            raise PolicyConfigError(f"duplicate policy_id: {rule.policy_id}")
        seen.add(rule.policy_id)
        cond = rule.when
        if not (cond.min_level or cond.levels or cond.signal_groups or cond.attack_chains):
            raise PolicyConfigError(f"{rule.policy_id}: condition is empty")
        for group in cond.signal_groups:
            if not group:
                raise PolicyConfigError(f"{rule.policy_id}: empty signal group")
            unknown = sorted(set(group) - known)
            if unknown:
                raise PolicyConfigError(f"{rule.policy_id}: unknown signals {unknown}")


def active_policy_rules(rules: Sequence[PolicyRule] | None) -> tuple[PolicyRule, ...]:
    """Return configured rules or the defaults."""
    return tuple(DEFAULT_POLICY_RULES if rules is None else rules)


def _matches(
    cond: PolicyCondition, level: EmailRiskLevel, signals: set[str], family: AttackFamily
) -> bool:
    if not (cond.min_level or cond.levels or cond.signal_groups or cond.attack_chains):
        return False
    if cond.min_level is not None and (
        level == EmailRiskLevel.UNKNOWN or level_rank(level) < level_rank(cond.min_level)
    ):
        return False
    if cond.levels and level not in cond.levels:
        return False
    if any(not (signals & set(group)) for group in cond.signal_groups):
        return False
    return not (cond.attack_chains and family not in cond.attack_chains)


def _merge_decisions(matched: Sequence[MatchedPolicy]) -> list[PolicyDecision]:
    merged = {d for m in matched for d in m.decisions}
    if not merged:
        return [PolicyDecision.ALLOW]
    if any(DECISION_SEVERITY[d] > DECISION_SEVERITY[PolicyDecision.WARN] for d in merged):
        merged.discard(PolicyDecision.WARN)
    merged.discard(PolicyDecision.ALLOW)
    return sorted(merged, key=lambda d: -DECISION_SEVERITY[d])


def verification_guidance(
    decisions: Sequence[PolicyDecision], signals: set[str]
) -> VerificationGuidance:
    """Out-of-band verification advice; required for HUMAN_VERIFY / BLOCK_ACTION."""
    required = bool({PolicyDecision.HUMAN_VERIFY, PolicyDecision.BLOCK_ACTION} & set(decisions))
    if not required:
        return VerificationGuidance(required=False)
    do_not_trust = list(DO_NOT_TRUST_BASE)
    if "bank_account_change" in signals or "invoice_fraud" in signals:
        do_not_trust.append("Bank details supplied in this message or its attachments")
    if signals & {"credential_request", *URL_RISK_SIGNALS}:
        do_not_trust.append("Links in this message, including 'verify' or sign-in links")
    return VerificationGuidance(
        required=True, instruction=VERIFICATION_INSTRUCTION, do_not_trust=do_not_trust
    )


def evaluate_email_policy(
    *,
    level: EmailRiskLevel,
    signals: Iterable[str],
    attack_chain: AttackFamily,
    rules: Sequence[PolicyRule] | None = None,
) -> PolicyGateResult:
    """Evaluate policies in order and return the merged advisory outcome."""
    signal_set = set(signals)
    matched = [
        MatchedPolicy(policy_id=r.policy_id, decisions=list(r.decisions), rationale=r.rationale)
        for r in active_policy_rules(rules)
        if _matches(r.when, level, signal_set, attack_chain)
    ]
    decisions = _merge_decisions(matched)
    actions = [DECISION_ACTIONS[d] for d in decisions]
    if decisions != [PolicyDecision.ALLOW]:
        actions.extend(text for signal, text in SIGNAL_ACTIONS if signal in signal_set)
    return PolicyGateResult(
        primary_decision=decisions[0],
        decisions=decisions,
        matched_policies=matched,
        recommended_actions=actions,
        verification=verification_guidance(decisions, signal_set),
    )
