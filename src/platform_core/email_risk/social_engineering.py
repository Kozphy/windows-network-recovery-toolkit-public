"""Social-engineering pressure signals: urgency, secrecy, authority pressure.

Key invariants:
    * Signature/disclaimer blocks are excluded (``EmailText.active``), so a
      "CEO" title or "This email is confidential" footer does not fire.
    * Secrecy requires an imperative ("keep this confidential", "don't tell
      anyone"), not a descriptive disclaimer ("this e-mail is confidential").
    * Weak time words ("today", "now") count only inside request sentences and
      only when at least two appear; strong urgency terms fire on their own.
    * Authority pressure is not evaluated for internal senders — managers
      legitimately give instructions to their teams. A senior title in the
      display name only counts when the sender is implausible for that title
      (consumer mailbox, lookalike domain, org-name claim).

Side effects:
    None.
"""

from __future__ import annotations

import re

from .domains import sender_relationship
from .identity import role_claim_implausible
from .lexicon import AUTHORITY_ROLE, has_directive
from .models import EmailRiskConfig, EmailRiskEvidence, EvidenceSource, ParsedEmail
from .normalization import EmailText, clip, first_match
from .scoring import build_evidence

URGENCY_STRONG = re.compile(
    r"(?i:\b(?:urgent(?:ly)?|immediately|asap|as\s+soon\s+as\s+possible|right\s+(?:now|away)|"
    r"at\s+once|without\s+delay|time[-\s]sensitive|within\s+(?:the\s+next\s+)?\d+\s*"
    r"(?:min(?:ute)?s?|hours?|hrs?)|by\s+end\s+of\s+(?:the\s+)?day)\b)"
    r"|緊急|立即|立刻|馬上|趕快|趕緊|儘快|盡快|急件|速辦|今天(?:之內|內)?(?:處理|完成|辦好|匯)|\d+\s*分鐘內"
)
URGENCY_WEAK = re.compile(r"(?i:\b(?:today|now|quickly|soon|deadline|eod)\b)|今天|今日")

SECRECY = re.compile(
    r"(?i:\bkeep\s+(?:this|it|that|everything|the\s+matter)\s+(?:strictly\s+)?"
    r"(?:confidential|private|secret|quiet|between\s+us|to\s+yourself)\b"
    r"|\b(?:don'?t|do\s+not)\s+(?:tell|inform|share\s+(?:this\s+)?with|mention\s+(?:this\s+)?to|"
    r"discuss\s+(?:this\s+)?with|contact|call|cc|copy|involve|loop\s+in)\s+"
    r"(?:anyone|anybody|others|other\s+people|finance|accounting|the\s+finance\s+team|"
    r"your\s+(?:manager|boss|colleagues?|team)|the\s+office)\b"
    r"|\b(?:don'?t|do\s+not)\s+call\s+(?:me\s+)?to\s+(?:confirm|verify)\b"
    r"|\bbetween\s+(?:you\s+and\s+me|us\s+only)\b"
    r"|\bthis\s+is\s+(?:strictly\s+)?(?:confidential|a\s+secret)\b"
    r"|\bthis\s+is\s+a\s+(?:confidential|secret)\s+(?:matter|request|project|deal|acquisition)\b)"
    r"|不要(?:告訴|跟|和|讓)(?:其他人|任何人|別人|同事|財務|會計|主管)"
    r"|別(?:告訴|跟)(?:其他人|任何人|別人)"
    r"|(?:請|務必|先|要|需要|絕對)保密|保密一下"
    r"|不要(?:聯絡|聯繫|打給|通知)(?:財務|會計|其他人|任何人)"
    r"|不要打電話(?:確認|查證|給我)|不要(?:電話|打來)確認"
)


def _urgency(text: EmailText, config: EmailRiskConfig) -> EmailRiskEvidence | None:
    strong = first_match(URGENCY_STRONG, text.active())
    if strong:
        segment, match = strong
        return build_evidence(
            "urgency",
            observed=clip(match.group(0)),
            source=segment.source,
            detail="Message pressures the recipient to act quickly.",
            config=config,
        )
    weak_hits: list[tuple[EvidenceSource, str]] = []
    for segment in text.active():
        if has_directive(segment.text):
            weak_hits.extend(
                (segment.source, m.group(0)) for m in URGENCY_WEAK.finditer(segment.text)
            )
    if len(weak_hits) >= 2:
        return build_evidence(
            "urgency",
            observed=", ".join(clip(h[1], 20) for h in weak_hits[:3]),
            source=weak_hits[0][0],
            detail="Multiple time-pressure cues inside request sentences.",
            config=config,
        )
    return None


def _secrecy(text: EmailText, config: EmailRiskConfig) -> EmailRiskEvidence | None:
    hit = first_match(SECRECY, text.active())
    if not hit:
        return None
    segment, match = hit
    return build_evidence(
        "secrecy_request",
        observed=clip(match.group(0)),
        source=segment.source,
        detail="Message asks the recipient to keep the request secret or avoid normal verification.",
        config=config,
    )


def _authority(
    email: ParsedEmail, text: EmailText, config: EmailRiskConfig
) -> EmailRiskEvidence | None:
    sender = email.from_address
    if sender is None or sender_relationship(sender.domain, config) == "internal":
        return None
    for segment in text.active():
        role = AUTHORITY_ROLE.search(segment.text)
        if role and has_directive(segment.text):
            return build_evidence(
                "authority_pressure",
                observed=clip(segment.text),
                source=segment.source,
                detail=f"Instruction is framed around the authority of '{role.group(0)}'.",
                config=config,
            )
    display_role = AUTHORITY_ROLE.search(sender.display_name)
    if display_role and role_claim_implausible(sender, config)[0]:
        directive = next(
            (
                s
                for s in text.active()
                if s.source == EvidenceSource.EMAIL_BODY and has_directive(s.text)
            ),
            None,
        )
        if directive:
            return build_evidence(
                "authority_pressure",
                observed=f"sender '{display_role.group(0)}' requests: {clip(directive.text, 60)}",
                source=EvidenceSource.DISPLAY_NAME,
                detail="Sender presents a senior title and issues direct instructions.",
                config=config,
            )
    return None


def detect_social_engineering_signals(
    email: ParsedEmail, text: EmailText, config: EmailRiskConfig
) -> list[EmailRiskEvidence]:
    """Return urgency / secrecy / authority-pressure evidence."""
    return [
        item
        for item in (
            _urgency(text, config),
            _secrecy(text, config),
            _authority(email, text, config),
        )
        if item is not None
    ]
