"""QR-phishing signals: semantic QR requests and locally decoded QR artifacts.

Signals:
    ``qr_code_present``            QR decoded from an image part (artifact).
    ``qr_code_scan_request``       Asks the reader to scan / use a QR code.
    ``qr_code_return_request``     Asks the reader to send a QR code back
                                   (login / device-link / group QR hand-over).
    ``messaging_group_qr_request`` Asks for a messaging-group QR (e.g. "create
                                   a LINE group and send me its QR code");
                                   subsumes ``qr_code_return_request``.

Key invariants:
    * A bare mention of "QR code" never fires: scan requests need a directive,
      a purpose clause, or an imperative scan verb; return requests need a
      send-back target (me / us / back / 回傳 / 給我); group requests need a
      group or messaging-platform context plus a return/creation request.
    * Matching uses the folded view (``Q R code``, ``QR碼``, ``二維碼``,
      ``L I N E``, ``L1NE``); evidence keeps the normalized sentence and, when
      folding was needed, the escaped original line in ``observed_raw``.
    * Decoded payloads are classified and redacted as strings. URLs are
      canonicalized with ``website_risk.urls`` and handed to the caller for
      ``website_risk`` scoring — they are never visited here.

Side effects:
    None beyond the injected decoder (CPU-only, in memory).
"""

from __future__ import annotations

import re

from src.platform_core.website_risk.urls import UrlNormalizationError, normalize_url

from .channel_migration import EXCLUDE as CHANNEL_EXCLUDE
from .channel_migration import GROUP_ACTION, platforms_in
from .lexicon import has_directive
from .models import (
    EmailRiskConfig,
    EmailRiskEvidence,
    EvidenceSource,
    ParsedEmail,
    QrArtifact,
    QrDecodeStatus,
    QrPayload,
    UrlOrigin,
)
from .normalization import EmailText, Segment, clip, raw_view
from .privacy import mask_address, mask_digits, redact_free_text, redact_url
from .qr_decode import MAX_DECODE_BYTES, QrDecodeError, QrDecoder
from .scoring import build_evidence

MAX_PAYLOAD_CHARS = 2048
MAX_PAYLOADS_PER_IMAGE = 5

QR_TERM = re.compile(r"(?<![A-Za-z0-9])QR(?: code)?(?![A-Za-z0-9])", re.IGNORECASE)
CODE_REF = re.compile(r"(?i)\b(?:this|the|that|attached|below|following)\s+code\b")
SCAN_ZH_CODE = re.compile(r"掃碼|扫码")
SCAN_START = re.compile(
    r"(?i)^\s*(?:please\s+|pls\s+|kindly\s+)?scan\b|^\s*(?:請|您|你)?\s*(?:用手機)?(?:掃描|掃|扫描|扫)"
)
SCAN_VERB = re.compile(r"(?i:\bscan(?:ning)?\b)|掃描|掃|扫描|扫")
SCAN_PURPOSE = re.compile(
    r"(?i:\bto\s+(?:verify|log\s*in|login|sign\s*in|access|keep|continue|join|confirm|pay|"
    r"unlock|re-?activate|update|validate|authenticate|restore|receive|claim|avoid|link)\b)"
    r"|驗證|登入|登錄|登录|确认|確認|付款|支付|加入|解鎖|領取|领取|啟用|更新|綁定|绑定"
)
USE_QR = re.compile(
    r"(?i)\b(?:join|log\s*in|login|sign\s*in|verify|pay|access|connect|register|link)\b"
    r"[^.?!]{0,30}?\b(?:using|with|via|through|by\s+scanning)\s+(?:this|the|that|attached|"
    r"below|our|my)?\s*QR\b"
    r"|\buse\s+(?:this|the|that|attached|below|my|our)\s+QR(?: code)?\s+to\b"
    r"|(?:用|透過|通过|使用)(?:這個|此|下方|附件|以下)?(?:的)?\s*QR(?: code)?\s*(?:加入|登入|驗證|付款|綁定)"
)
RETURN_EN = re.compile(
    r"(?i)\b(?:send|forward|share|give|provide|text|email|message|pass)\s+(?:it\s+|them\s+)?"
    r"(?:back\s+)?(?:to\s+)?(?:me|us)\b[^.?!]{0,40}?QR\b"
    r"|\b(?:send|forward|share|return|pass|text|email)\b[^.?!]{0,40}?QR(?: code)?\b"
    r"[^.?!]{0,25}?\b(?:back|to\s+(?:me|us|my)|with\s+(?:me|us))\b"
    r"|\b(?:send|forward|pass|return)\s+back\b[^.?!]{0,40}?QR\b"
    r"|\b(?:reply|respond)\s+with\b[^.?!]{0,30}?QR\b"
    r"|\b(?:take\s+a\s+)?screenshot\b[^.?!]{0,40}?QR\b"
    r"|QR(?: code)?\b[^.?!]{0,40}?\b(?:send|forward|text|email)\s+(?:it|them)\s+"
    r"(?:back\s+)?to\s+(?:me|us)\b"
)
RETURN_ZH = re.compile(
    r"(?:回傳|傳回|回覆|回給我|發回|传回|回传)[^。！？!?]{0,12}?QR"
    r"|QR(?: code)?[^。！？!?]{0,12}?(?:傳給我|傳送給我|寄給我|發給我|給我|傳回|回傳|發我|傳我|"
    r"传给我|发给我|发我|给我)"
    r"|(?:把|將|将)[^。！？!?]{0,12}?QR(?: code)?[^。！？!?]{0,6}?(?:傳|寄|發|給|给|发)"
    r"|(?<![宣流遺自上相謠])傳\s*(?:一下|個|个)?[^。！？!?]{0,8}?QR"
    r"|截圖[^。！？!?]{0,12}?QR|QR(?: code)?[^。！？!?]{0,8}?截圖"
)
GROUP_CONTEXT = re.compile(r"(?i:\bgroups?(?:\s+chat)?\b|\bchat\s+room\b)|群組|群组|群")
FOR_ME = re.compile(r"(?i:\b(?:for|to)\s+(?:me|us)\b)|給我|给我|給我們")
EXCLUDE = re.compile(
    CHANNEL_EXCLUDE.pattern
    + r"|(?i:\bdownload\s+(?:our|the)\s+app\b|\brestaurant\s+menu\b|\bmenu\b)"
    r"|下載(?:我們的)?\s*(?:APP|App|app)|菜單"
)

_MESSAGING_INVITES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("LINE", re.compile(r"(?i)^(?:[a-z0-9-]+\.)*line\.me/(?:r/)?ti/g2?/")),
    ("WhatsApp", re.compile(r"(?i)^chat\.whatsapp\.com/")),
    ("Telegram", re.compile(r"(?i)^(?:t|telegram)\.me/(?:\+|joinchat/)")),
    ("Signal", re.compile(r"(?i)^signal\.group/")),
    ("WeChat", re.compile(r"(?i)^weixin\.qq\.com/g/")),
)
_CRYPTO_SCHEMES = ("bitcoin:", "ethereum:", "litecoin:", "tron:", "usdt:", "monero:")
_ORIGIN_BY_SOURCE = {
    EvidenceSource.ATTACHMENT: UrlOrigin.QR_ATTACHMENT,
    EvidenceSource.INLINE_IMAGE: UrlOrigin.QR_INLINE_IMAGE,
    EvidenceSource.HTML_DATA_URI: UrlOrigin.QR_HTML_DATA_URI,
}


def _window(segments: tuple[Segment, ...], idx: int) -> str:
    prev = segments[idx - 1].match_text if idx > 0 else ""
    return f"{prev} {segments[idx].match_text}"


def _is_scan_request(text: str) -> bool:
    if USE_QR.search(text):
        return True
    if not (QR_TERM.search(text) or CODE_REF.search(text) or SCAN_ZH_CODE.search(text)):
        return False
    if not (SCAN_VERB.search(text) or SCAN_ZH_CODE.search(text)):
        return False
    return bool(SCAN_START.search(text) or SCAN_PURPOSE.search(text) or has_directive(text))


def _is_return_request(text: str) -> bool:
    return bool(RETURN_EN.search(text) or RETURN_ZH.search(text))


def _is_group_qr_request(segments: tuple[Segment, ...], idx: int) -> bool:
    text = segments[idx].match_text
    if not QR_TERM.search(text):
        return False
    window = _window(segments, idx)
    if not (GROUP_CONTEXT.search(window) or platforms_in(window)):
        return False
    if _is_return_request(text):
        return True
    return bool(GROUP_ACTION.search(window) and FOR_ME.search(text))


def _semantic_evidence(
    signal: str, segment: Segment, detail: str, config: EmailRiskConfig
) -> EmailRiskEvidence:
    raw = raw_view(segment)
    evidence = build_evidence(
        signal,
        observed=clip(segment.text, 80),
        source=segment.source,
        detail=detail + (" Matched after Unicode/obfuscation normalization." if raw else ""),
        config=config,
    )
    evidence.observed_raw = raw
    return evidence


def detect_qr_requests(text: EmailText, config: EmailRiskConfig) -> list[EmailRiskEvidence]:
    """Return semantic QR request evidence (no image required)."""
    segments = text.active()
    found: dict[str, EmailRiskEvidence] = {}
    for idx, segment in enumerate(segments):
        match_text = segment.match_text
        if EXCLUDE.search(match_text):
            continue
        if "messaging_group_qr_request" not in found and _is_group_qr_request(segments, idx):
            platforms = platforms_in(_window(segments, idx))
            where = f" on {', '.join(platforms)}" if platforms else ""
            found["messaging_group_qr_request"] = _semantic_evidence(
                "messaging_group_qr_request",
                segment,
                f"Message asks for a messaging-group QR code{where}; handing over group or "
                "device-link QR codes gives the requester access.",
                config,
            )
        elif "qr_code_return_request" not in found and _is_return_request(match_text):
            found["qr_code_return_request"] = _semantic_evidence(
                "qr_code_return_request",
                segment,
                "Message asks the reader to send a QR code back; login or device-link QR "
                "codes can hand over account access.",
                config,
            )
        if "qr_code_scan_request" not in found and _is_scan_request(match_text):
            found["qr_code_scan_request"] = _semantic_evidence(
                "qr_code_scan_request",
                segment,
                "Message asks the reader to scan or use a QR code, which moves the link "
                "to a phone outside email link protection.",
                config,
            )
    if "messaging_group_qr_request" in found:
        found.pop("qr_code_return_request", None)
    order = ("messaging_group_qr_request", "qr_code_return_request", "qr_code_scan_request")
    return [found[s] for s in order if s in found]


def _mask_token(value: str) -> str:
    value = value.strip()
    return value if len(value) <= 8 else f"{value[:4]}…{value[-4:]}"


def classify_payload(text: str) -> QrPayload:
    """Classify and redact one decoded QR payload string (never opened)."""
    value = text.strip()
    truncated = len(value) > MAX_PAYLOAD_CHARS
    value = value[:MAX_PAYLOAD_CHARS]
    lower = value.lower()
    if lower.startswith(("http://", "https://", "www.")):
        try:
            normalized = normalize_url(value)
        except UrlNormalizationError:
            return QrPayload(
                kind="text", value=clip(redact_free_text(value), 120), truncated=truncated
            )
        host_path = normalized.url.split("://", 1)[1].rsplit("@", 1)[-1]
        platform = next((name for name, p in _MESSAGING_INVITES if p.match(host_path)), "")
        return QrPayload(
            kind="messaging_invite" if platform else "url",
            value=redact_url(normalized.url),
            url=normalized.url,
            platform=platform,
            truncated=truncated,
        )
    if lower.startswith("wifi:"):
        return QrPayload(
            kind="wifi_config",
            value=re.sub(r"(?i)(P:)([^;]*)", r"\1[REDACTED]", value),
            truncated=truncated,
        )
    if lower.startswith("otpauth"):
        redacted = re.sub(r"(?i)(secret=)[^&]*", r"\1[REDACTED]", value)
        return QrPayload(kind="otp_secret", value=clip(redacted, 120), truncated=truncated)
    if lower.startswith(_CRYPTO_SCHEMES):
        scheme, _, rest = value.partition(":")
        address = rest.split("?", 1)[0]
        return QrPayload(
            kind="crypto_payment", value=f"{scheme}:{_mask_token(address)}", truncated=truncated
        )
    if lower.startswith("mailto:"):
        address = value[7:].split("?", 1)[0]
        return QrPayload(
            kind="email_address", value=f"mailto:{mask_address(address)}", truncated=truncated
        )
    if lower.startswith(("tel:", "sms:", "smsto:")):
        return QrPayload(
            kind="phone_or_sms", value=clip(mask_digits(value), 60), truncated=truncated
        )
    if lower.startswith(("begin:vcard", "mecard:")):
        return QrPayload(kind="contact_card", value="[contact card]", truncated=truncated)
    return QrPayload(kind="text", value=clip(redact_free_text(value), 120), truncated=truncated)


def _decode_one(data: bytes, decoder: QrDecoder) -> tuple[QrDecodeStatus, list[QrPayload]]:
    try:
        texts = decoder(data)
    except QrDecodeError as exc:
        return ("too_large" if exc.reason == "too_large" else "invalid_image"), []
    except Exception:  # third-party decoders must never break analysis
        return "invalid_image", []
    payloads = [classify_payload(t) for t in texts[:MAX_PAYLOADS_PER_IMAGE] if t and t.strip()]
    return ("decoded" if payloads else "no_qr_found"), payloads


def decode_qr_images(
    email: ParsedEmail, config: EmailRiskConfig, decoder: QrDecoder | None
) -> list[QrArtifact]:
    """Decode QR codes from the message's in-memory image parts.

    Returns one ``QrArtifact`` per image with an explicit ``decode_status``;
    image bytes never leave this function.
    """
    artifacts: list[QrArtifact] = []
    for idx, image in enumerate(email.images):
        status: QrDecodeStatus
        payloads: list[QrPayload] = []
        if not config.qr_decode:
            status = "decoding_disabled"
        elif idx >= config.max_images_decoded:
            status = "skipped_limit"
        elif not image.data or image.size_bytes > MAX_DECODE_BYTES:
            status = "too_large"
        elif decoder is None:
            status = "decoder_unavailable"
        else:
            status, payloads = _decode_one(image.data, decoder)
        artifacts.append(
            QrArtifact(
                source=image.source,
                filename=image.filename,
                content_type=image.content_type,
                size_bytes=image.size_bytes,
                sha256=image.sha256,
                decode_status=status,
                payloads=payloads,
            )
        )
    return artifacts


def qr_url_origin(source: EvidenceSource) -> UrlOrigin:
    """Map an image source to the provenance tag used for its decoded URLs."""
    return _ORIGIN_BY_SOURCE.get(source, UrlOrigin.QR_ATTACHMENT)


def qr_present_evidence(
    artifacts: list[QrArtifact], config: EmailRiskConfig
) -> EmailRiskEvidence | None:
    """One ``qr_code_present`` item summarizing every decoded QR payload."""
    decoded = [(a, p) for a in artifacts for p in a.payloads]
    if not decoded:
        return None
    first_artifact, first_payload = decoded[0]
    kinds = sorted({p.kind for _, p in decoded})
    sources = sorted({a.source.value for a, _ in decoded})
    url_note = (
        " QR code decoded to a URL; URL was not visited." if any(p.url for _, p in decoded) else ""
    )
    return build_evidence(
        "qr_code_present",
        observed=first_payload.value,
        source=first_artifact.source,
        detail=(
            f"{len(decoded)} QR payload(s) decoded locally from {', '.join(sources)} "
            f"(kinds: {', '.join(kinds)}).{url_note} Decoding is not opening."
        ),
        config=config,
    )


__all__ = [
    "classify_payload",
    "decode_qr_images",
    "detect_qr_requests",
    "qr_present_evidence",
    "qr_url_origin",
]
