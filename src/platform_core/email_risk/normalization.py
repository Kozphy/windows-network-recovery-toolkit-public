"""Safe text normalization and segmentation for lexical detectors.

Key invariants:
    * NFKC folds full-width forms (``ＬＩＮＥ`` → ``LINE``); zero-width and
      bidi control characters are removed before matching.
    * Three views per segment, never mixed up:
        - ``raw``: the original line (forensic evidence, unmodified);
        - ``text``: NFKC + invisible-character removal (PR1 detectors);
        - ``folded``: ``text`` plus targeted de-obfuscation for matching only
          (``Q R code`` / ``QR-Code`` / ``QR碼`` / ``二維碼`` → ``QR code``;
          ``L I N E`` / ``L1NE`` → ``LINE``; Cyrillic/Greek look-alikes →
          Latin). Folding is never written back into evidence ``observed``.
    * Trailing signature/disclaimer blocks are excluded from directive
      detection so a title in a signature does not count as pressure.
    * Case is preserved in ``Segment.text`` (``LINE`` vs the word "line");
      detectors choose case sensitivity per pattern.

Side effects:
    None.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .models import EvidenceSource, ParsedEmail

_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")
_CONFUSABLES = str.maketrans(
    {
        "А": "A",
        "В": "B",
        "Е": "E",
        "І": "I",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "Ι": "I",
        "Ν": "N",
        "Ε": "E",
        "Ο": "O",
        "Ρ": "P",
        "а": "a",
        "е": "e",
        "і": "i",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
    }
)
_SEP = r"[\s.\-_·•*]{0,2}"
_QR_VARIANT = re.compile(
    rf"(?<![A-Za-z0-9])[Qq]{_SEP}[Rr](?:{_SEP}(?:[Cc][Oo][Dd][Ee]|碼|码|コード))?(?![A-Za-z0-9])"
    r"|二維碼|二维码|行動條碼|行动条码"
)
_LINE_VARIANT = re.compile(rf"(?<![A-Za-z0-9])L{_SEP}[I1l|!]{_SEP}N{_SEP}E(?![A-Za-z0-9])")
_WS = re.compile(r"[ \t\u00a0\u3000]+")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;])(?:\s+|(?=[^\x00-\x7f]))|(?<=[。！？；])\s*|\n+")
_SIGN_OFF = re.compile(
    r"^\s*(?:--\s*$|(?:best|kind|warm|warmest)?\s*regards\b|thanks\b|thank you\b|cheers\b|"
    r"sincerely\b|br,|此致|敬上|謝謝|感謝|順頌|祝好|敬祝)",
    re.IGNORECASE,
)
_MAX_SIGNATURE_LINES = 12


@dataclass(frozen=True)
class Segment:
    """One sentence-like unit of analyzable text with its origin.

    Key fields:
        text: NFKC-normalized sentence (used for evidence ``observed``).
        raw: Original line containing the sentence (forensic view).
        folded: De-obfuscated matching view of ``text``.
        normalized_changed: NFKC / invisible-character removal altered ``raw``.
    """

    source: EvidenceSource
    text: str
    in_signature: bool = False
    raw: str = ""
    folded: str = ""
    normalized_changed: bool = False

    @property
    def match_text(self) -> str:
        """Text detectors should match against (folded view when available)."""
        return self.folded or self.text


@dataclass(frozen=True)
class EmailText:
    """Normalized message text split into segments."""

    segments: tuple[Segment, ...]

    def active(self) -> tuple[Segment, ...]:
        """Segments outside the signature/disclaimer block."""
        return tuple(s for s in self.segments if not s.in_signature)


def normalize_text(value: str) -> str:
    """NFKC-normalize, drop invisible characters, and collapse horizontal whitespace."""
    text = unicodedata.normalize("NFKC", value or "")
    text = _INVISIBLE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(_WS.sub(" ", line).strip() for line in text.split("\n"))


def normalize_line(value: str) -> str:
    """Single-line form of ``normalize_text``."""
    text = _INVISIBLE.sub("", unicodedata.normalize("NFKC", value or ""))
    return _WS.sub(" ", text).strip()


def fold_for_matching(text: str) -> str:
    """De-obfuscate QR / LINE spellings and look-alike letters (matching view only)."""
    folded = text.translate(_CONFUSABLES)
    folded = _QR_VARIANT.sub("QR code", folded)
    return _LINE_VARIANT.sub("LINE", folded)


def escape_invisible(text: str) -> str:
    """Show zero-width / bidi characters as ``<U+XXXX>`` so evidence reveals them."""
    return _INVISIBLE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", text)


def raw_view(segment: Segment, limit: int = 160) -> str:
    """Escaped original line when normalization or folding changed the match text.

    Case-only folding (``QR Code`` → ``QR code``) is not forensic-relevant and
    does not populate the raw view.
    """
    folded_changed = segment.folded.casefold() != segment.text.casefold()
    if not segment.raw or not (segment.normalized_changed or folded_changed):
        return ""
    return clip(escape_invisible(segment.raw), limit)


def _paired_lines(value: str) -> list[tuple[str, str]]:
    raw = (value or "").replace("\r\n", "\n").replace("\r", "\n")
    pairs: list[tuple[str, str]] = []
    for raw_line in raw.split("\n"):
        norm = normalize_line(raw_line)
        if norm:
            pairs.append((raw_line.strip(), norm))
    return pairs


def _segments_for_line(
    source: EvidenceSource, raw_line: str, norm_line: str, *, in_signature: bool
) -> list[Segment]:
    changed = norm_line != _WS.sub(" ", raw_line).strip()
    return [
        Segment(
            source,
            sentence,
            in_signature=in_signature,
            raw=raw_line,
            folded=fold_for_matching(sentence),
            normalized_changed=changed,
        )
        for sentence in _split(norm_line)
    ]


def _signature_start(lines: list[str]) -> int | None:
    for idx, line in enumerate(lines):
        if idx == 0 or len(line) > 40:
            continue
        if _SIGN_OFF.match(line) and len(lines) - idx <= _MAX_SIGNATURE_LINES:
            return idx
    return None


def _split(text: str) -> list[str]:
    return [part.strip() for part in _SENTENCE_SPLIT.split(text) if part and part.strip()]


def build_email_text(email: ParsedEmail) -> EmailText:
    """Build normalized segments from subject and body (HTML used when no plain text)."""
    segments: list[Segment] = []
    for raw_line, norm_line in _paired_lines(email.subject):
        segments.extend(
            _segments_for_line(
                EvidenceSource.EMAIL_SUBJECT, raw_line, norm_line, in_signature=False
            )
        )

    pairs = _paired_lines(email.body_text or email.body_html_text)
    sig_at = _signature_start([norm for _, norm in pairs])
    for idx, (raw_line, norm_line) in enumerate(pairs):
        in_sig = sig_at is not None and idx >= sig_at
        segments.extend(
            _segments_for_line(EvidenceSource.EMAIL_BODY, raw_line, norm_line, in_signature=in_sig)
        )
    return EmailText(tuple(segments))


def first_match(
    pattern: re.Pattern[str], segments: tuple[Segment, ...]
) -> tuple[Segment, re.Match[str]] | None:
    """Return the first segment/match pair for ``pattern``."""
    for segment in segments:
        match = pattern.search(segment.text)
        if match:
            return segment, match
    return None


def clip(value: str, limit: int = 80) -> str:
    """Trim a matched phrase for evidence output."""
    value = value.strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"
