"""Payment / financial-instruction signals.

Signals:
    ``payment_intent``, ``wire_transfer_request``, ``bank_account_change``,
    ``invoice_fraud``, ``gift_card_request``, ``crypto_payment_request``.

Key invariants:
    * Topic words alone ("payment methods have changed", "we accept bank
      transfer") do not fire; a request/directive cue or an explicitly
      instructional phrase ("payment instructions", "wire the funds") is needed.
    * ``invoice_fraud`` requires an invoice reference *plus* a banking change
      or an overdue-and-wire combination — a normal invoice notice does not fire.
    * ``gift_card_request`` requires code/photo/purchase-quantity language, the
      hallmark of gift-card scams, not a retailer's gift-card promotion.
    * Account numbers are never echoed; evidence stores matched phrases only.

Side effects:
    None.
"""

from __future__ import annotations

import re

from .lexicon import has_directive
from .models import EmailRiskConfig, EmailRiskEvidence
from .normalization import EmailText, Segment, clip
from .scoring import build_evidence

PAYMENT_EXPLICIT = re.compile(
    r"(?i:\b(?:payment\s+(?:instructions?|details)|wire\s+instructions|banking\s+details|"
    r"make\s+(?:a|the)\s+payment|process\s+(?:a|the|this)\s+payment|"
    r"send\s+(?:the\s+)?(?:payment|funds|money)|transfer\s+(?:the\s+)?(?:funds|money|payment)|"
    r"release\s+(?:the\s+)?(?:payment|funds)|pay\s+(?:the|this|that)\s+"
    r"(?:invoice|vendor|supplier|amount|bill|balance))\b)"
    r"|(?:付款|匯款|轉帳|支付|打款)(?:資訊|資料|指示|明細|帳號|方式給你)"
    r"|(?:給你|傳給你|告訴你|發給你).{0,6}(?:付款|匯款|轉帳)"
)
PAYMENT_TOPIC = re.compile(
    r"(?i:\b(?:payments?|pay|funds|remit(?:tance)?|transfer)\b)|付款|匯款|轉帳|支付|打款|匯錢|轉錢|撥款"
)

WIRE = re.compile(
    r"(?i:\b(?:wire\s+transfer|bank\s+transfer|telegraphic\s+transfer|swift\s+(?:transfer|payment)|"
    r"wire\s+(?:the\s+)?(?:funds|money|payment|amount)|(?:send|make)\s+a\s+wire)\b)"
    r"|電匯|銀行轉帳|跨行轉帳|國際匯款|匯到.{0,12}帳戶|轉到.{0,12}帳戶|匯款到"
)
WIRE_SELF_IMPERATIVE = re.compile(r"(?i:\bwire\s+(?:the\s+)?(?:funds|money|payment|amount)\b)")

BANK_CHANGE = re.compile(
    r"(?i:\b(?:(?:change[ds]?|update[ds]?|new|different|alternate|alternative)\s+"
    r"(?:our\s+|the\s+|my\s+)?(?:bank(?:ing)?|account|beneficiary|remittance)\s+"
    r"(?:details|information|info|account|number|instructions)"
    r"|(?:bank(?:ing)?|account)\s+(?:details|information)\s+(?:have|has)\s+(?:changed|been\s+updated)"
    r"|new\s+beneficiary|beneficiary\s+(?:change|update|details)|(?:changed|switched)\s+(?:our\s+)?banks?)\b)"
    r"|(?:修改|更改|變更|更換|換|更新)了?(?:收款|銀行|匯款)(?:帳戶|帳號|戶頭)"
    r"|(?:修改|更改|變更|更換|換|更新)了?戶頭"
    r"|新的?(?:收款|銀行)(?:帳戶|帳號)"
    r"|收款(?:帳戶|帳號)(?:已|有)?(?:變更|更改|更新|改了)"
)

INVOICE = re.compile(r"(?i:\binvoices?\b|\bbilling\s+statement\b)|發票|請款單|帳單")
OVERDUE = re.compile(
    r"(?i:\b(?:overdue|past\s+due|outstanding|unpaid|final\s+notice)\b)|逾期|未付|尚未付款"
)

GIFT_CARD = re.compile(
    r"(?i:\b(?:gift\s*cards?|itunes\s+cards?|apple\s+(?:gift\s+)?cards?|google\s+play\s+cards?|"
    r"steam\s+cards?|amazon\s+cards?|prepaid\s+cards?)\b)"
    r"|禮物卡|禮品卡|點數卡|儲值卡|遊戲點數"
)
GIFT_CARD_SCAM_CUE = re.compile(
    r"(?i:\b(?:send\s+(?:me\s+)?(?:the\s+)?(?:codes?|pictures?|photos?|pins?|numbers?)|scratch|"
    r"card\s+(?:codes?|numbers?|pins?)|claim\s+codes?|redemption\s+codes?|"
    r"(?:buy|purchase|get)\s+(?:me\s+)?(?:some|\d+|a\s+few|several))\b)"
    r"|序號|卡號|拍照|刮開|傳給我|買\s*\d+|購買\s*\d+|幫我買"
)

CRYPTO = re.compile(
    r"(?i:\b(?:bitcoin|btc|usdt|tether|ethereum|crypto(?:currency)?|wallet\s+address)\b)"
    r"|加密貨幣|虛擬貨幣|比特幣|泰達幣|以太幣|錢包地址"
)
CRYPTO_ACTION = re.compile(r"(?i:\b(?:send|transfer|pay|deposit|wire)\b)|轉|匯|付|存入")


def _first(
    pattern: re.Pattern[str], segments: tuple[Segment, ...], *, directive: bool
) -> tuple[Segment, str] | None:
    for segment in segments:
        match = pattern.search(segment.text)
        if match and (not directive or has_directive(segment.text)):
            return segment, match.group(0)
    return None


def _payment_intent(
    segments: tuple[Segment, ...], config: EmailRiskConfig
) -> EmailRiskEvidence | None:
    hit = _first(PAYMENT_EXPLICIT, segments, directive=False) or _first(
        PAYMENT_TOPIC, segments, directive=True
    )
    if not hit:
        return None
    segment, phrase = hit
    return build_evidence(
        "payment_intent",
        observed=clip(phrase),
        source=segment.source,
        detail="Message requests or announces instructions for a payment.",
        config=config,
    )


def _wire(segments: tuple[Segment, ...], config: EmailRiskConfig) -> EmailRiskEvidence | None:
    hit = _first(WIRE_SELF_IMPERATIVE, segments, directive=False) or _first(
        WIRE, segments, directive=True
    )
    if not hit:
        return None
    segment, phrase = hit
    return build_evidence(
        "wire_transfer_request",
        observed=clip(phrase),
        source=segment.source,
        detail="Message asks for a bank/wire transfer.",
        config=config,
    )


def _bank_change(
    segments: tuple[Segment, ...], config: EmailRiskConfig
) -> EmailRiskEvidence | None:
    hit = _first(BANK_CHANGE, segments, directive=False)
    if not hit:
        return None
    segment, phrase = hit
    return build_evidence(
        "bank_account_change",
        observed=clip(phrase),
        source=segment.source,
        detail="Message announces or requests a change of beneficiary / bank account details.",
        config=config,
    )


def _invoice_fraud(
    segments: tuple[Segment, ...],
    config: EmailRiskConfig,
    *,
    bank_change: bool,
    wire: bool,
) -> EmailRiskEvidence | None:
    invoice = _first(INVOICE, segments, directive=False)
    if not invoice:
        return None
    overdue = _first(OVERDUE, segments, directive=False)
    if bank_change:
        reason = "invoice reference combined with a bank-account change"
    elif wire and overdue:
        reason = "overdue invoice combined with a wire-transfer request"
    else:
        return None
    segment, phrase = invoice
    return build_evidence(
        "invoice_fraud",
        observed=clip(phrase),
        source=segment.source,
        detail=f"Pattern consistent with invoice redirection: {reason}.",
        config=config,
    )


def _gift_card(segments: tuple[Segment, ...], config: EmailRiskConfig) -> EmailRiskEvidence | None:
    card = _first(GIFT_CARD, segments, directive=False)
    cue = _first(GIFT_CARD_SCAM_CUE, segments, directive=False)
    if not card or not cue:
        return None
    return build_evidence(
        "gift_card_request",
        observed=f"{clip(card[1], 30)} + {clip(cue[1], 30)}",
        source=card[0].source,
        detail="Message asks for gift cards and their codes/photos — a common payment-fraud pattern.",
        config=config,
    )


def _crypto(segments: tuple[Segment, ...], config: EmailRiskConfig) -> EmailRiskEvidence | None:
    for segment in segments:
        term = CRYPTO.search(segment.text)
        if term and CRYPTO_ACTION.search(segment.text) and has_directive(segment.text):
            return build_evidence(
                "crypto_payment_request",
                observed=clip(term.group(0)),
                source=segment.source,
                detail="Message asks for a cryptocurrency transfer.",
                config=config,
            )
    return None


def detect_payment_signals(text: EmailText, config: EmailRiskConfig) -> list[EmailRiskEvidence]:
    """Return payment/financial-instruction evidence."""
    segments = text.active()
    bank_change = _bank_change(segments, config)
    wire = _wire(segments, config)
    out = [
        item
        for item in (
            _payment_intent(segments, config),
            wire,
            bank_change,
            _invoice_fraud(
                segments, config, bank_change=bank_change is not None, wire=wire is not None
            ),
            _gift_card(segments, config),
            _crypto(segments, config),
        )
        if item is not None
    ]
    return out
