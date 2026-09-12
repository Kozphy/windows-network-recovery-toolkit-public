"""Privacy redaction helpers for HAR and browser evidence.

Module responsibility:
    Strip or mask sensitive headers and query parameters from URLs/HARs before
    persistence or report rendering.

System placement:
    Called from HAR compare and browser-profile runners before audit/export.

Key invariants:
    Sensitive header names (cookie, authorization, api keys) are redacted.
    Query params matching token/secret patterns have values replaced with
    ``[REDACTED]``; names are kept for structural analysis.

Side effects:
    None (pure transforms returning new structures).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
    }
)

_SENSITIVE_QUERY_RE = re.compile(
    r"(token|key|secret|code|session|auth|jwt|sig|signature|password|passwd|access_token|refresh_token)",
    re.IGNORECASE,
)


def redact_url(url: str) -> tuple[str, list[str]]:
    """Redact sensitive query-parameter values from a URL.

    Parameters matching ``_SENSITIVE_QUERY_RE`` (e.g. ``token``, ``key``,
    ``session``, ``auth``, ``jwt``) have their values replaced with
    ``[REDACTED]``.  Parameter names are preserved for structural analysis.

    Args:
        url: Raw URL string that may contain sensitive query parameters.

    Returns:
        A 2-tuple of:
            redacted_url (str): URL with sensitive query-param values replaced.
            notes (list[str]): Names of redacted parameters (e.g. ``["query:token"]``).
    """
    notes: list[str] = []
    parts = urlsplit(url)
    if not parts.query:
        return url, notes
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out: list[tuple[str, str]] = []
    for k, v in pairs:
        if _SENSITIVE_QUERY_RE.search(k):
            out.append((k, "[REDACTED]"))
            notes.append(f"query:{k}")
        else:
            out.append((k, v))
    new_query = urlencode(out)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)), notes


def redact_headers(headers: list[dict[str, Any]] | dict[str, Any] | None) -> tuple[Any, list[str]]:
    """Redact sensitive header values while preserving header presence.

    Headers whose names are in ``SENSITIVE_HEADER_NAMES`` (Cookie, Set-Cookie,
    Authorization, Proxy-Authorization, X-API-Key, X-Auth-Token, X-Access-Token)
    have their values replaced with ``[REDACTED]``.  The header name is retained
    so that the classifier can observe that a cookie *was* present.

    Args:
        headers: Request or response headers as a list of ``{"name": ..., "value": ...}``
            dicts, a plain ``{name: value}`` dict, or ``None``.

    Returns:
        A 2-tuple of:
            redacted_headers: Same structure as input with sensitive values replaced.
            notes (list[str]): Names of redacted headers (e.g. ``["header:Cookie"]``).
    """
    notes: list[str] = []
    if headers is None:
        return headers, notes
    if isinstance(headers, dict):
        out: dict[str, Any] = {}
        for k, v in headers.items():
            if str(k).lower() in SENSITIVE_HEADER_NAMES:
                out[k] = "[REDACTED]"
                notes.append(f"header:{k}")
            else:
                out[k] = v
        return out, notes
    out_list: list[dict[str, Any]] = []
    for h in headers:
        name = str(h.get("name") or h.get("Name") or "")
        item = dict(h)
        if name.lower() in SENSITIVE_HEADER_NAMES:
            item["value"] = "[REDACTED]"
            notes.append(f"header:{name}")
        out_list.append(item)
    return out_list, notes


def redact_har(har: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Produce a deep-copy of a HAR archive with all secrets redacted.

    For each entry: applies ``redact_url`` to request URLs, ``redact_headers``
    to request and response headers, replaces request ``postData.text`` with
    ``[REDACTED]``, and replaces response ``content.text`` with ``[REDACTED]``.

    Args:
        har: Raw HAR dict as parsed from a ``.har`` file (must have a ``log.entries``
            list following the HAR 1.2/1.3 schema).

    Returns:
        A 2-tuple of:
            redacted_har (dict): Sanitised HAR dict suitable for structural analysis.
            notes (list[str]): Sorted, deduplicated redaction notes describing which
                fields were replaced (e.g. ``["header:Cookie", "query:token"]``).
    """
    notes: list[str] = []
    log = har.get("log") or {}
    entries_in = log.get("entries") or []
    entries_out: list[dict[str, Any]] = []
    for raw in entries_in:
        entry = {
            "request": dict(raw.get("request") or {}),
            "response": dict(raw.get("response") or {}),
            "timings": raw.get("timings"),
            "time": raw.get("time"),
            "_resourceType": raw.get("_resourceType"),
            "_fromCache": raw.get("_fromCache"),
            "_error": raw.get("_error"),
            "_was_served_from_service_worker": raw.get("_was_served_from_service_worker")
            or raw.get("_wasServedFromServiceWorker"),
        }
        req = entry["request"]
        if "url" in req:
            req["url"], n = redact_url(str(req["url"]))
            notes.extend(n)
        if "headers" in req:
            req["headers"], n = redact_headers(req.get("headers"))
            notes.extend(n)
        resp = entry["response"]
        if "headers" in resp:
            resp["headers"], n = redact_headers(resp.get("headers"))
            notes.extend(n)
        # Drop bodies that may contain secrets
        if "postData" in req:
            req["postData"] = {
                "mimeType": (req.get("postData") or {}).get("mimeType"),
                "text": "[REDACTED]",
            }
            notes.append("request.postData")
        if "content" in resp and isinstance(resp["content"], dict):
            resp["content"] = {
                "size": resp["content"].get("size"),
                "mimeType": resp["content"].get("mimeType"),
                "text": "[REDACTED]",
            }
            notes.append("response.content")
        entries_out.append(entry)
    return {"log": {"version": log.get("version", "1.2"), "entries": entries_out}}, sorted(
        set(notes)
    )
