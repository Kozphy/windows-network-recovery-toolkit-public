"""Safe, inert email parsing for ``.eml`` / RFC 822 text / JSON fixtures.

Key invariants:
    * Attachments are measured, never written to disk or executed. Image parts
      (attachments, inline images, HTML ``data:`` URIs) are kept in memory —
      size-capped and excluded from serialization — solely for local QR
      decoding.
    * HTML is reduced to inert text; scripts/styles are dropped and no remote
      resource (image, CSS, iframe) is ever fetched. Remote ``<img src>``
      values are ignored entirely.
    * URLs are extracted as strings, canonicalized with
      ``website_risk.urls.normalize_url``, de-duplicated, and tagged with every
      origin (plain text, HTML text, HTML link) — never opened.
    * Malformed input yields a ``ParsedEmail`` with ``parse_warnings`` (and
      ``parse_ok=False`` when nothing usable was recovered) instead of raising;
      only unreadable/oversized files raise ``EmailParseError``.

Side effects:
    ``load_email_source`` reads one local file. No network access.
"""

from __future__ import annotations

import base64
import binascii
import email
import hashlib
import json
import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.policy import compat32
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from src.platform_core.website_risk.urls import UrlNormalizationError, normalize_url

from .models import (
    AttachmentMeta,
    AuthenticationSummary,
    AuthVerdict,
    EmailAddress,
    EvidenceSource,
    ExtractedUrl,
    ImagePart,
    ParsedEmail,
    UrlOrigin,
)

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_URLS = 100
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGES = 20

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`\]\)\}]+", re.IGNORECASE)
_URL_LIKE = re.compile(r"(?i)^\s*(?:https?:|www\.|javascript:|data:|vbscript:)")
_IGNORED_HREF = re.compile(r"(?i)^\s*(?:mailto:|tel:|sms:|#|/|\.|$)")
_DATA_IMAGE = re.compile(r"(?is)^\s*data:(image/[a-z0-9.+\-]+);base64,(.*)$")
_IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")
_AUTH_METHOD_RE = {
    "spf": re.compile(r"\bspf\s*=\s*([a-z]+)", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim\s*=\s*([a-z]+)", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc\s*=\s*([a-z]+)", re.IGNORECASE),
}
_VERDICT_ALIASES = {"hardfail": "fail", "bestguesspass": "neutral"}


class EmailParseError(ValueError):
    """Raised when an email source cannot be read at all."""


@dataclass
class InertHtml:
    """Visible text, link targets, and embedded ``data:`` images from HTML."""

    text: str
    links: list[str] = field(default_factory=list)
    data_images: list[tuple[str, str]] = field(default_factory=list)


class _InertHTML(HTMLParser):
    """Collect visible text and link targets without rendering anything."""

    _SKIP = frozenset({"script", "style", "head", "noscript", "template", "iframe", "object"})
    _BLOCK = frozenset({"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "table", "td"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []
        self.data_images: list[tuple[str, str]] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
            return
        if tag in self._BLOCK:
            self.parts.append("\n")
        for name, value in attrs:
            if name in {"href", "action"} and value:
                self.links.append(value.strip())
            elif tag == "img" and name == "src" and value:
                # Only self-contained data: images are kept; remote src is never touched.
                match = _DATA_IMAGE.match(value)
                if match and len(self.data_images) < MAX_IMAGES:
                    self.data_images.append((match.group(1).lower(), match.group(2)))

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


def html_to_inert_parts(html: str) -> InertHtml:
    """Return visible text, link targets, and ``data:`` images without rendering HTML."""
    parser = _InertHTML()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # HTMLParser can raise on pathological input
        return InertHtml(text=re.sub(r"<[^>]+>", " ", html))
    text = "".join(parser.parts)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return InertHtml(text=text.strip(), links=parser.links, data_images=parser.data_images)


def html_to_inert_text(html: str) -> tuple[str, list[str]]:
    """Return ``(visible_text, link_targets)`` from HTML without rendering it."""
    parts = html_to_inert_parts(html)
    return parts.text, parts.links


def extract_url_records(
    sources: list[tuple[UrlOrigin, str]],
    hrefs: list[str] | None = None,
) -> tuple[list[ExtractedUrl], int]:
    """Extract, canonicalize, and de-duplicate URLs while keeping provenance.

    Args:
        sources: ``(origin, text)`` pairs scanned for ``http(s)://`` / ``www.``.
        hrefs: HTML ``href`` / form ``action`` targets (origin ``html_href``).

    Returns:
        ``(records, rejected_count)`` — rejected counts URL-like strings that
        failed normalization (malformed, ``javascript:``, ``data:`` ...).
        ``mailto:`` / ``tel:`` / relative links are ignored, not rejected.
    """
    records: dict[str, ExtractedUrl] = {}
    rejected = 0
    candidates: list[tuple[UrlOrigin, str]] = []
    for origin, text in sources:
        candidates.extend((origin, m.group(0)) for m in _URL_RE.finditer(text or ""))
    for href in hrefs or []:
        if _URL_LIKE.match(href):
            candidates.append((UrlOrigin.HTML_HREF, href))
        elif not _IGNORED_HREF.match(href):
            rejected += 1
    for origin, raw in candidates:
        try:
            normalized = normalize_url(raw)
        except UrlNormalizationError:
            rejected += 1
            continue
        key = normalized.dedupe_key
        existing = records.get(key)
        if existing is not None:
            existing.occurrences += 1
            if origin not in existing.origins:
                existing.origins.append(origin)
            continue
        if len(records) >= MAX_URLS:
            continue
        records[key] = ExtractedUrl(url=normalized.url, host=normalized.host, origins=[origin])
    return list(records.values()), rejected


def extract_urls(*texts: str, extra: list[str] | None = None) -> list[str]:
    """Extract, canonicalize, and de-duplicate http(s)/www URLs as plain strings."""
    records, _ = extract_url_records(
        [(UrlOrigin.BODY_TEXT, text) for text in texts],
        [u for u in (extra or []) if re.match(r"(?i)https?://|www\.", u)],
    )
    return [r.url for r in records]


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _image_part(
    source: EvidenceSource, filename: str, ctype: str, data: bytes, warnings: list[str]
) -> ImagePart:
    if len(data) > MAX_IMAGE_BYTES:
        warnings.append(f"image_too_large:{source.value}")
        return ImagePart(source=source, filename=filename, content_type=ctype, size_bytes=len(data))
    return ImagePart(
        source=source,
        filename=filename,
        content_type=ctype,
        size_bytes=len(data),
        sha256=_sha256(data),
        data=data,
    )


def _data_uri_images(items: list[tuple[str, str]], warnings: list[str]) -> list[ImagePart]:
    images: list[ImagePart] = []
    for ctype, payload in items:
        compact = re.sub(r"\s+", "", payload)
        if len(compact) > (MAX_IMAGE_BYTES * 4) // 3 + 4:
            warnings.append("image_too_large:html_data_uri")
            continue
        try:
            data = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            warnings.append("invalid_data_uri")
            continue
        images.append(_image_part(EvidenceSource.HTML_DATA_URI, "", ctype, data, warnings))
    return images


def _is_image(ctype: str, filename: str) -> bool:
    return ctype.startswith("image/") or filename.lower().endswith(_IMAGE_EXTENSIONS)


def _decode(value: Any, warnings: list[str], name: str) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value)))).strip()
    except Exception:  # malformed encoded-words must not abort parsing
        warnings.append(f"header_decode_failed:{name}")
        return str(value).strip()


def _addresses(raw: str, warnings: list[str], name: str) -> list[EmailAddress]:
    if not raw:
        return []
    out: list[EmailAddress] = []
    for display, addr in getaddresses([raw]):
        addr = addr.strip()
        if addr and "@" in addr and not addr.startswith("@") and not addr.endswith("@"):
            out.append(EmailAddress(display_name=display.strip(), address=addr))
        elif display or addr:
            warnings.append(f"malformed_address:{name}")
    if not out and raw.strip():
        warnings.append(f"no_valid_address:{name}")
    return out


def _verdict(raw: str, warnings: list[str]) -> AuthVerdict:
    token = _VERDICT_ALIASES.get(raw.lower(), raw.lower())
    try:
        return AuthVerdict(token)
    except ValueError:
        warnings.append(f"unrecognized_auth_verdict:{raw}")
        return AuthVerdict.NONE


def parse_authentication(
    auth_results: list[str],
    received_spf: list[str],
    *,
    trusted_authserv_ids: list[str] | None = None,
    warnings: list[str] | None = None,
) -> AuthenticationSummary:
    """Parse SPF / DKIM / DMARC verdicts.

    Only the topmost ``Authentication-Results`` header is used (or the topmost
    one whose authserv-id is trusted, when configured) because lower headers can
    be injected by the sender.
    """
    warn = warnings if warnings is not None else []
    chosen = ""
    authserv = ""
    for header in auth_results:
        server = header.split(";", 1)[0].strip().split()[0] if header.strip() else ""
        if trusted_authserv_ids and server.lower() not in {s.lower() for s in trusted_authserv_ids}:
            continue
        chosen, authserv = header, server
        break
    if auth_results and not chosen:
        warn.append("no_trusted_authentication_results")

    summary = AuthenticationSummary(
        headers_present=bool(chosen or received_spf), authserv_id=authserv
    )
    for method, pattern in _AUTH_METHOD_RE.items():
        match = pattern.search(chosen)
        if match:
            setattr(summary, method, _verdict(match.group(1), warn))
    if summary.spf == AuthVerdict.MISSING and received_spf:
        first = received_spf[0].strip().split()
        if first:
            summary.spf = _verdict(first[0], warn)
    return summary


def _part_text(part: Message, warnings: list[str]) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    if not isinstance(payload, bytes):
        return str(payload)
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        warnings.append(f"unknown_charset:{charset}")
        return payload.decode("utf-8", errors="replace")


def _finish(
    parsed: ParsedEmail, url_sources: list[tuple[UrlOrigin, str]], hrefs: list[str]
) -> ParsedEmail:
    records, rejected = extract_url_records(url_sources, hrefs)
    parsed.url_records = records
    parsed.urls = [r.url for r in records]
    parsed.rejected_url_count = rejected
    if len(parsed.images) > MAX_IMAGES:
        parsed.parse_warnings.append(f"images_truncated:{len(parsed.images)}")
        parsed.images = parsed.images[:MAX_IMAGES]
    parsed.parse_ok = parsed.analyzable()
    if not parsed.parse_ok:
        parsed.parse_warnings.append("no_analyzable_content")
    return parsed


def _parse_message(msg: Message, *, trusted_authserv_ids: list[str] | None) -> ParsedEmail:
    warnings: list[str] = [f"mime_defect:{type(d).__name__}" for d in msg.defects]

    def header(name: str) -> str:
        return _decode(msg.get(name), warnings, name)

    def headers(name: str) -> list[str]:
        return [_decode(v, warnings, name) for v in (msg.get_all(name) or [])]

    from_list = _addresses(header("From"), warnings, "from")
    sender_list = _addresses(header("Sender"), warnings, "sender")
    return_path = ""
    rp = _addresses(header("Return-Path"), warnings, "return_path")
    if rp:
        return_path = rp[0].address

    plain: list[str] = []
    html_text: list[str] = []
    links: list[str] = []
    attachments: list[AttachmentMeta] = []
    images: list[ImagePart] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = _decode(part.get_filename(), warnings, "filename")
        inline_image = ctype.startswith("image/") and disposition != "attachment"
        if disposition == "attachment" or filename or inline_image:
            raw = part.get_payload(decode=True)
            data = raw if isinstance(raw, bytes) else b""
            is_inline = disposition != "attachment" and bool(inline_image or part.get("Content-ID"))
            attachments.append(
                AttachmentMeta(
                    filename=filename,
                    content_type=ctype,
                    size_bytes=len(data),
                    sha256=_sha256(data) if data else "",
                    inline=is_inline,
                )
            )
            if data and _is_image(ctype, filename):
                source = EvidenceSource.INLINE_IMAGE if is_inline else EvidenceSource.ATTACHMENT
                images.append(_image_part(source, filename, ctype, data, warnings))
            continue
        if ctype == "text/plain":
            plain.append(_part_text(part, warnings))
        elif ctype == "text/html":
            inert = html_to_inert_parts(_part_text(part, warnings))
            html_text.append(inert.text)
            links.extend(inert.links)
            images.extend(_data_uri_images(inert.data_images, warnings))

    auth_headers = headers("Authentication-Results")
    received_spf = headers("Received-SPF")
    body_text = "\n".join(p for p in plain if p).strip()
    body_html_text = "\n".join(p for p in html_text if p).strip()
    parsed = ParsedEmail(
        source_format="eml",
        parse_warnings=warnings,
        from_address=from_list[0] if from_list else None,
        sender=sender_list[0] if sender_list else None,
        reply_to=_addresses(header("Reply-To"), warnings, "reply_to"),
        return_path=return_path,
        to=_addresses(header("To"), warnings, "to"),
        cc=_addresses(header("Cc"), warnings, "cc"),
        subject=header("Subject"),
        message_id=header("Message-ID"),
        body_text=body_text,
        body_html_text=body_html_text,
        received=headers("Received"),
        authentication_results=auth_headers,
        received_spf=received_spf,
        authentication=parse_authentication(
            auth_headers,
            received_spf,
            trusted_authserv_ids=trusted_authserv_ids,
            warnings=warnings,
        ),
        attachments=attachments,
        images=images,
    )
    return _finish(
        parsed,
        [(UrlOrigin.BODY_TEXT, body_text), (UrlOrigin.HTML_TEXT, body_html_text)],
        links,
    )


def parse_eml_bytes(data: bytes, *, trusted_authserv_ids: list[str] | None = None) -> ParsedEmail:
    """Parse raw RFC 822 bytes into an inert ``ParsedEmail``."""
    if len(data) > MAX_INPUT_BYTES:
        raise EmailParseError(f"email exceeds {MAX_INPUT_BYTES} bytes")
    try:
        msg = email.message_from_bytes(data, policy=compat32)
    except Exception as exc:  # defensive: stdlib parser is lenient but not total
        return ParsedEmail(parse_ok=False, parse_warnings=[f"parse_failed:{type(exc).__name__}"])
    return _parse_message(msg, trusted_authserv_ids=trusted_authserv_ids)


def parse_eml_text(text: str, *, trusted_authserv_ids: list[str] | None = None) -> ParsedEmail:
    """Parse RFC 822 text (e.g. pasted "show original" source)."""
    return parse_eml_bytes(
        text.encode("utf-8", errors="replace"), trusted_authserv_ids=trusted_authserv_ids
    )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _json_attachment(
    item: dict[str, Any], warnings: list[str]
) -> tuple[AttachmentMeta, ImagePart | None]:
    filename = str(item.get("filename") or "")
    ctype = str(item.get("content_type") or "")
    encoded = item.get("content_base64")
    data = b""
    if isinstance(encoded, str) and encoded:
        if len(encoded) > (MAX_IMAGE_BYTES * 4) // 3 + 4:
            warnings.append("image_too_large:attachment")
        else:
            try:
                data = base64.b64decode(re.sub(r"\s+", "", encoded), validate=True)
            except (binascii.Error, ValueError):
                warnings.append("invalid_attachment_base64")
    inline = bool(item.get("inline"))
    meta = AttachmentMeta(
        filename=filename,
        content_type=ctype,
        size_bytes=len(data) if data else int(item.get("size_bytes") or 0),
        sha256=_sha256(data) if data else "",
        inline=inline,
    )
    image = None
    if data and _is_image(ctype, filename):
        source = EvidenceSource.INLINE_IMAGE if inline else EvidenceSource.ATTACHMENT
        image = _image_part(source, filename, ctype, data, warnings)
    return meta, image


def parse_email_json(
    obj: dict[str, Any], *, trusted_authserv_ids: list[str] | None = None
) -> ParsedEmail:
    """Parse a structured JSON fixture.

    Accepts ``{"raw_eml": "..."}`` (delegates to the RFC 822 parser) or an
    ``email`` object with header-like keys (``from``, ``reply_to``, ``subject``,
    ``body_text``, ``body_html``, ``authentication_results``, ...). Attachments
    may carry ``content_base64`` (image bytes are used only for local QR
    decoding).
    """
    nested = obj.get("email")
    body: dict[str, Any] = nested if isinstance(nested, dict) else obj
    if isinstance(body.get("raw_eml"), str):
        parsed = parse_eml_text(body["raw_eml"], trusted_authserv_ids=trusted_authserv_ids)
        parsed.source_format = "json"
        return parsed

    warnings: list[str] = []

    def addrs(key: str) -> list[EmailAddress]:
        return _addresses(", ".join(_as_list(body.get(key))), warnings, key)

    from_list = addrs("from")
    sender_list = addrs("sender")
    rp = addrs("return_path")
    inert = html_to_inert_parts(str(body.get("body_html") or ""))
    body_text = str(body.get("body_text") or "")
    auth_headers = _as_list(body.get("authentication_results"))
    received_spf = _as_list(body.get("received_spf"))
    attachments: list[AttachmentMeta] = []
    images = _data_uri_images(inert.data_images, warnings)
    for item in body.get("attachments") or []:
        if not isinstance(item, dict):
            continue
        meta, image = _json_attachment(item, warnings)
        attachments.append(meta)
        if image is not None:
            images.append(image)
    parsed = ParsedEmail(
        source_format="json",
        parse_warnings=warnings,
        from_address=from_list[0] if from_list else None,
        sender=sender_list[0] if sender_list else None,
        reply_to=addrs("reply_to"),
        return_path=rp[0].address if rp else "",
        to=addrs("to"),
        cc=addrs("cc"),
        subject=str(body.get("subject") or ""),
        message_id=str(body.get("message_id") or ""),
        body_text=body_text,
        body_html_text=inert.text,
        received=_as_list(body.get("received")),
        authentication_results=auth_headers,
        received_spf=received_spf,
        authentication=parse_authentication(
            auth_headers,
            received_spf,
            trusted_authserv_ids=trusted_authserv_ids,
            warnings=warnings,
        ),
        attachments=attachments,
        images=images,
    )
    return _finish(
        parsed,
        [(UrlOrigin.BODY_TEXT, body_text), (UrlOrigin.HTML_TEXT, inert.text)],
        inert.links,
    )


def load_email_source(
    path: Path, *, trusted_authserv_ids: list[str] | None = None
) -> tuple[ParsedEmail, dict[str, Any]]:
    """Load ``.eml`` / RFC 822 text / ``.json`` fixture from disk.

    Returns:
        ``(parsed_email, org_context)`` where ``org_context`` is the optional
        ``org_context`` object embedded in JSON fixtures (empty otherwise).

    Raises:
        EmailParseError: file missing, unreadable, oversized, or invalid JSON.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise EmailParseError(f"cannot read {path}: {exc}") from exc
    if size > MAX_INPUT_BYTES:
        raise EmailParseError(f"email exceeds {MAX_INPUT_BYTES} bytes")
    data = path.read_bytes()
    if path.suffix.lower() == ".json":
        try:
            obj = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EmailParseError(f"invalid JSON fixture: {exc}") from exc
        if not isinstance(obj, dict):
            raise EmailParseError("JSON fixture must be an object")
        raw_context = obj.get("org_context")
        context: dict[str, Any] = raw_context if isinstance(raw_context, dict) else {}
        trusted = trusted_authserv_ids or list(context.get("trusted_authserv_ids") or [])
        return parse_email_json(obj, trusted_authserv_ids=trusted or None), context
    return parse_eml_bytes(data, trusted_authserv_ids=trusted_authserv_ids), {}
