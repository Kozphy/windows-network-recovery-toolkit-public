"""Shared bilingual (English / Traditional Chinese) lexicon for detectors.

Patterns are deliberately conservative: detectors combine a *topic* term with
a *request/directive* cue in the same sentence rather than firing on a bare
keyword, which keeps newsletters and signatures from triggering.

Side effects:
    None.
"""

from __future__ import annotations

import re

EXEC_ROLE = re.compile(
    r"(?i:\b(?:ceo|cfo|coo|cto|chief\s+\w+\s+officer|chair(?:man|woman|person)|president|"
    r"founder|managing\s+director|executive\s+director|general\s+manager|vice\s+president)\b)"
    r"|執行長|董事長|總經理|總裁|副總|財務長|老闆"
)

AUTHORITY_ROLE = re.compile(
    EXEC_ROLE.pattern
    + r"|(?i:\b(?:director|manager|supervisor|boss|head\s+of\s+\w+|finance\s+director)\b)"
    r"|經理|主管|處長|協理|總監|上司|董事"
)

FINANCE_ROLE = re.compile(
    r"(?i:\b(?:finance|financial|accounting|accounts\s+(?:payable|receivable)|payroll|"
    r"treasury|controller|billing)\b)|財務|會計|出納|薪資|帳務"
)

EXEC_LOCAL_TOKENS = frozenset(
    {"ceo", "cfo", "coo", "cto", "chairman", "president", "founder", "boss", "director"}
)
FINANCE_LOCAL_TOKENS = frozenset({"finance", "accounting", "accounts", "payroll", "treasury"})

SELF_CLAIM = re.compile(
    r"(?i:\b(?:i\s+am|i'm|this\s+is)\s+(?:the\s+|your\s+|our\s+)?(?:company\s+)?"
    r"(?:ceo|cfo|coo|chair(?:man|woman)|president|founder|managing\s+director)\b"
    r"|\bas\s+(?:the\s+|your\s+)?(?:ceo|cfo|chair(?:man|woman)|president)\b)"
    r"|我是(?:公司的?)?(?:執行長|董事長|總經理|總裁|財務長|老闆)"
)

DIRECTIVE = re.compile(
    r"(?i:\b(?:please|pls|kindly|i\s+need\s+you|need\s+you\s+to|i\s+want\s+you|want\s+you\s+to|"
    r"can\s+you|could\s+you|would\s+you|make\s+sure|you\s+must|you\s+need\s+to|you\s+should|"
    r"go\s+ahead|let\s+me\s+know|i\s+will\s+send\s+you|i'll\s+send\s+you|send\s+me|"
    r"get\s+back\s+to\s+me|needs\s+you|wants\s+you|asked\s+(?:me|you|us)|instructed|requires?\s+you)\b"
    r"|^\s*(?:create|set\s+up|add|join|send|buy|purchase|transfer|wire|pay|process|contact|call|"
    r"text|message|reply|update|change|move|switch|keep|do\s+not|don't|confirm|arrange|handle|scan)\b)"
    r"|請|麻煩|幫我|幫忙|需要你|你要|你先|務必|交代|要求你|指示|吩咐|安排一下|處理一下"
)


def has_directive(text: str) -> bool:
    """Return True when ``text`` reads as a request or instruction."""
    return DIRECTIVE.search(text) is not None
