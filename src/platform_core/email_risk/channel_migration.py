"""External communication-channel migration (``external_channel_migration``).

Detects requests to move a conversation off corporate email to LINE, WhatsApp,
Telegram, Signal, WeChat, SMS, or a personal mailbox.

Key invariants:
    * A platform mention alone never fires; the same sentence must contain a
      migration action ("add me on", "create a group", "continue on",
      "建立 … 群組", "加我", "改用").
    * "LINE" is matched case-sensitively (or with an explicit qualifier such
      as "line group" / "LINE ID" / "加line") so the English word "line" does
      not trigger.
    * Marketing/official-account phrasing ("follow us on LINE", "官方帳號",
      "LINE Pay") is excluded.

Side effects:
    None.
"""

from __future__ import annotations

import re

from .models import EmailRiskConfig, EmailRiskEvidence
from .normalization import EmailText, Segment, clip, raw_view
from .scoring import build_evidence

PLATFORMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "LINE",
        re.compile(
            r"\bLINE\b|\bLine\s+(?:app|group|ID|account|chat)\b"
            r"|(?i:\bline\s+(?:group|id|app|account|chat)\b)"
            r"|(?i:line)\s*(?:群組|群|帳號|好友|ID)"
            r"|(?:加我?|改用|用|透過|私)\s*(?i:line)"
        ),
    ),
    ("WhatsApp", re.compile(r"(?i)\bwhats\s*app\b|\bwa\.me/")),
    ("Telegram", re.compile(r"(?i)\btelegram\b|\bt\.me/|電報")),
    (
        "Signal",
        re.compile(
            r"\bSignal\s+(?:app|messenger|chat|group)\b|\bon\s+Signal\b|(?i:signal)\s*(?:群組|帳號)"
        ),
    ),
    ("WeChat", re.compile(r"(?i)\bwe\s*chat\b|\bweixin\b|微信")),
    ("SMS", re.compile(r"(?i)\bsms\b|\btext\s+me\b|\bimessage\b|簡訊")),
    (
        "personal email",
        re.compile(
            r"(?i)\b(?:personal|private)\s+(?:e-?mail|gmail|inbox|mailbox|address)\b"
            r"|私人(?:信箱|郵箱|email|mail)|個人(?:信箱|郵箱)"
        ),
    ),
)

DIRECT_ACTION = re.compile(
    r"(?i:\b(?:add\s+me|add\s+(?:you|u)\s+(?:on|to)|"
    r"contact\s+me|reach\s+me|message\s+me|text\s+me|dm\s+me|ping\s+me|"
    r"chat\s+with\s+me|talk\s+(?:to\s+me\s+)?on|"
    r"continue\s+(?:this\s+|our\s+|the\s+)?(?:conversation\s+|discussion\s+|chat\s+)?(?:on|in|via|over)|"
    r"(?:move|switch|take)\s+(?:this\s+|our\s+|the\s+)?(?:conversation\s+|discussion\s+|chat\s+)?"
    r"(?:to|over\s+to|onto)|let'?s\s+(?:use|talk|chat|continue)|please\s+use|"
    r"send\s+me\s+your|give\s+me\s+your|share\s+your|what'?s\s+your|"
    r"reply\s+(?:to\s+me\s+)?(?:on|via)|send\s+(?:it|this|them|the\s+\w+)\s+to\s+my|"
    r"forward\s+(?:it|this|them)\s+to\s+my|email\s+me\s+(?:at|on))\b)"
    r"|加我|改用|改成|換到|轉到|移到|聯絡我|聯繫我|私訊我|傳訊息給我|寄到我|傳到我"
)

# "create / join / invite" only count as migration when a group or chat is the object.
GROUP_ACTION = re.compile(
    r"(?i:\b(?:create|set\s+up|start|open|make|join|invite|add\s+(?:you|me|us)\s+to)\b)"
    r"|建立|建個|建一個|創建|拉|開|加入|邀請|進|入"
)
GROUP_WORD = re.compile(r"(?i:\b(?:group|group\s+chat|chat\s+room)\b)|群組|群")

EXCLUDE = re.compile(
    r"(?i:\bfollow\s+us\b|\bofficial\s+(?:line\s+)?account\b|\bline\s*pay\b|\bunsubscribe\b)"
    r"|官方帳號|官方LINE|官方Line|LINE\s*Pay"
)


def platforms_in(text: str) -> list[str]:
    """Return messaging platforms named in ``text`` (use the folded matching view)."""
    return [name for name, pattern in PLATFORMS if pattern.search(text)]


def _is_migration_request(text: str) -> bool:
    if DIRECT_ACTION.search(text):
        return True
    return bool(GROUP_ACTION.search(text) and GROUP_WORD.search(text))


def detect_channel_migration(text: EmailText, config: EmailRiskConfig) -> list[EmailRiskEvidence]:
    """Return at most one ``external_channel_migration`` evidence item."""
    platforms: list[str] = []
    first: Segment | None = None
    for segment in text.active():
        match_text = segment.match_text
        if EXCLUDE.search(match_text) or not _is_migration_request(match_text):
            continue
        found = platforms_in(match_text)
        if not found:
            continue
        first = first or segment
        platforms.extend(p for p in found if p not in platforms)
    if not platforms or first is None:
        return []
    joined = ", ".join(platforms)
    raw = raw_view(first)
    evidence = build_evidence(
        "external_channel_migration",
        observed=joined,
        source=first.source,
        detail=(
            f"Message asks to move communication from corporate email to {joined} "
            f'(e.g. "{clip(first.text, 60)}")'
            + ("; matched after Unicode/obfuscation normalization." if raw else ".")
        ),
        config=config,
    )
    evidence.observed_raw = raw
    return [evidence]
