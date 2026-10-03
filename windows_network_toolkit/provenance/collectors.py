"""Collectors for domain provenance — fixture-first, optional online adapters.

Module responsibility:
    Gather DNS, RDAP, and IP-geo observations as structured dicts/signals.

System placement:
    After normalization; feeds scoring. Online adapters (RDAP.org, country.is)
    run only when ``online=True``.

Key invariants:
    * Offline/fixture mode never opens network sockets for RDAP/GeoIP.
    * Collectors emit raw observations; they do not score operator country.
    * Infrastructure geo is labeled distinctly from RDAP registrant country.

Side effects:
    Optional HTTPS GETs when ``online=True``.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from windows_network_toolkit.provenance.models import ProvenanceSignal, SignalKind
from windows_network_toolkit.provenance.normalize import extract_cctld, normalize_country

HttpGet = Callable[[str, float], dict[str, Any]]

# Operator-facing weights (sum can exceed 1; scoring applies uncertainty).
OPERATOR_WEIGHTS = {
    "cctld": 0.45,
    "rdap_registrant_country": 0.40,
    "rdap_admin_country": 0.25,
    "rdap_registrant_org_country": 0.10,
}


def _default_http_get_json(url: str, timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "windows-network-toolkit-domain-provenance/1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — explicit online opt-in
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body) if body else {}


def resolve_dns_a(host: str, *, timeout: float = 5.0) -> list[str]:
    """Resolve A records for ``host`` (best-effort, offline-friendly).

    Args:
        host: Normalized hostname.
        timeout: Unused socket default; kept for API symmetry.

    Returns:
        List of IPv4 strings (may be empty).
    """
    _ = timeout
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, socket.gaierror):
        return []
    addrs: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip and ip not in addrs:
            addrs.append(ip)
    return addrs[:12]


def fetch_rdap_domain(
    host: str,
    *,
    http_get: HttpGet | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Fetch domain RDAP via rdap.org bootstrap HTTP.

    Args:
        host: Normalized hostname.
        http_get: Optional injectable GET returning JSON dict.
        timeout: Request timeout seconds.

    Returns:
        RDAP JSON dict, or ``{"error": ...}`` on failure.
    """
    getter = http_get or _default_http_get_json
    url = f"https://rdap.org/domain/{host}"
    try:
        return getter(url, timeout)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
        return {"error": str(exc)[:240], "ldhName": host}


def fetch_country_is(
    ip: str,
    *,
    http_get: HttpGet | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Fetch IP country from country.is (infrastructure signal only).

    Args:
        ip: IPv4/IPv6 address.
        http_get: Optional injectable GET returning JSON dict.
        timeout: Request timeout seconds.

    Returns:
        JSON dict with ``country`` when successful.
    """
    getter = http_get or _default_http_get_json
    url = f"https://api.country.is/{ip}"
    try:
        return getter(url, timeout)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
        return {"error": str(exc)[:240], "ip": ip}


def _entity_vcard_country(entity: dict[str, Any]) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return normalize_country(entity.get("country"))
    rows = vcard[1]
    if not isinstance(rows, list):
        return ""
    for row in rows:
        if not isinstance(row, list) or len(row) < 4:
            continue
        if row[0] == "adr":
            # ADR value is often a list; country is last element.
            val = row[3]
            if isinstance(val, list) and val:
                return normalize_country(str(val[-1]))
            return normalize_country(str(val))
        if row[0] == "country-name":
            return normalize_country(str(row[3]))
    return normalize_country(entity.get("country"))


def _entities_by_role(rdap: dict[str, Any], role: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ent in rdap.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if role in roles:
            out.append(ent)
        # Nested entities (common in RDAP).
        for nested in ent.get("entities") or []:
            if isinstance(nested, dict):
                nroles = [str(r).lower() for r in (nested.get("roles") or [])]
                if role in nroles:
                    out.append(nested)
    return out


def signals_from_fixture(fixture: dict[str, Any], host: str) -> list[ProvenanceSignal]:
    """Build provenance signals from a deterministic fixture dict.

    Expected fixture keys (all optional except useful ones):
        ``dns.a``, ``rdap``, ``ip_geo`` (list of ``{ip, country}``),
        ``asn`` (``{country, org}``).

    Args:
        fixture: Loaded JSON object.
        host: Normalized hostname (used for ccTLD).

    Returns:
        List of ``ProvenanceSignal`` rows.
    """
    signals: list[ProvenanceSignal] = []

    cctld = extract_cctld(host)
    if cctld:
        signals.append(
            ProvenanceSignal(
                id="cctld",
                kind=SignalKind.OPERATOR,
                country=cctld,
                weight=OPERATOR_WEIGHTS["cctld"],
                source="normalize.cctld",
                detail=f"Country-code TLD implies operator geography candidate {cctld}.",
                observed=f".{cctld.lower()}",
            )
        )

    rdap = fixture.get("rdap") or {}
    if isinstance(rdap, dict) and rdap:
        signals.extend(_signals_from_rdap(rdap, source="fixture.rdap"))

    for row in fixture.get("ip_geo") or []:
        if not isinstance(row, dict):
            continue
        country = normalize_country(row.get("country"))
        ip = str(row.get("ip") or "")
        if country:
            signals.append(
                ProvenanceSignal(
                    id="ip_geo",
                    kind=SignalKind.INFRASTRUCTURE,
                    country=country,
                    weight=0.0,
                    source="fixture.ip_geo",
                    detail="Hosting/edge IP geography (infrastructure only).",
                    observed=ip or country,
                )
            )

    asn = fixture.get("asn") or {}
    if isinstance(asn, dict):
        country = normalize_country(asn.get("country"))
        if country:
            signals.append(
                ProvenanceSignal(
                    id="asn_country",
                    kind=SignalKind.INFRASTRUCTURE,
                    country=country,
                    weight=0.0,
                    source="fixture.asn",
                    detail=f"ASN/org geography (infrastructure only): {asn.get('org') or ''}".strip(),
                    observed=str(asn.get("org") or country),
                )
            )

    dns = fixture.get("dns") or {}
    for ip in dns.get("a") or []:
        signals.append(
            ProvenanceSignal(
                id="dns_a",
                kind=SignalKind.CONTEXT,
                country="",
                weight=0.0,
                source="fixture.dns",
                detail="Resolved A record (context; geo via ip_geo when present).",
                observed=str(ip),
            )
        )

    return signals


def _signals_from_rdap(rdap: dict[str, Any], *, source: str) -> list[ProvenanceSignal]:
    signals: list[ProvenanceSignal] = []
    if rdap.get("error"):
        signals.append(
            ProvenanceSignal(
                id="rdap_error",
                kind=SignalKind.CONTEXT,
                source=source,
                detail="RDAP lookup failed or incomplete.",
                observed=str(rdap.get("error"))[:200],
            )
        )
        return signals

    registrant = _entities_by_role(rdap, "registrant")
    for ent in registrant[:1]:
        country = _entity_vcard_country(ent)
        if country:
            signals.append(
                ProvenanceSignal(
                    id="rdap_registrant_country",
                    kind=SignalKind.OPERATOR,
                    country=country,
                    weight=OPERATOR_WEIGHTS["rdap_registrant_country"],
                    source=source,
                    detail="RDAP registrant country (operator-facing).",
                    observed=country,
                )
            )
        # Optional org-level country hint from publicId / remarks is skipped —
        # only explicit country fields count.

    admin = _entities_by_role(rdap, "administrative")
    for ent in admin[:1]:
        country = _entity_vcard_country(ent)
        if country:
            signals.append(
                ProvenanceSignal(
                    id="rdap_admin_country",
                    kind=SignalKind.OPERATOR,
                    country=country,
                    weight=OPERATOR_WEIGHTS["rdap_admin_country"],
                    source=source,
                    detail="RDAP administrative contact country (operator-facing).",
                    observed=country,
                )
            )

    # Top-level country rarely present; treat as weak registrant hint if no entity.
    top = normalize_country(rdap.get("country"))
    if top and not any(s.id == "rdap_registrant_country" for s in signals):
        signals.append(
            ProvenanceSignal(
                id="rdap_registrant_country",
                kind=SignalKind.OPERATOR,
                country=top,
                weight=OPERATOR_WEIGHTS["rdap_registrant_country"],
                source=source,
                detail="RDAP top-level country field (operator-facing).",
                observed=top,
            )
        )

    return signals


def collect_live_signals(
    host: str,
    *,
    online: bool,
    http_get: HttpGet | None = None,
    resolve_a: Callable[[str], list[str]] | None = None,
    timeout: float = 12.0,
) -> list[ProvenanceSignal]:
    """Collect live signals; online adapters gated by ``online``.

    Args:
        host: Normalized hostname.
        online: When False, only local DNS + ccTLD (no RDAP/country.is).
        http_get: Injectable HTTP JSON getter for tests.
        resolve_a: Injectable DNS resolver for tests.
        timeout: Network timeout seconds.

    Returns:
        List of signals. Without ``online``, RDAP/GeoIP are omitted with a
        context limitation signal.
    """
    signals: list[ProvenanceSignal] = []
    cctld = extract_cctld(host)
    if cctld:
        signals.append(
            ProvenanceSignal(
                id="cctld",
                kind=SignalKind.OPERATOR,
                country=cctld,
                weight=OPERATOR_WEIGHTS["cctld"],
                source="normalize.cctld",
                detail=f"Country-code TLD implies operator geography candidate {cctld}.",
                observed=f".{cctld.lower()}",
            )
        )

    resolver = resolve_a or (lambda h: resolve_dns_a(h, timeout=timeout))
    addrs = resolver(host)
    for ip in addrs:
        signals.append(
            ProvenanceSignal(
                id="dns_a",
                kind=SignalKind.CONTEXT,
                source="dns.getaddrinfo",
                detail="Resolved A record.",
                observed=ip,
            )
        )

    if not online:
        signals.append(
            ProvenanceSignal(
                id="online_disabled",
                kind=SignalKind.CONTEXT,
                source="collectors",
                detail="Online RDAP.org / country.is skipped (pass --online to enable).",
                observed="offline",
            )
        )
        return signals

    rdap = fetch_rdap_domain(host, http_get=http_get, timeout=timeout)
    signals.extend(_signals_from_rdap(rdap, source="rdap.org"))

    for ip in addrs[:5]:
        geo = fetch_country_is(ip, http_get=http_get, timeout=min(timeout, 8.0))
        country = normalize_country(geo.get("country"))
        if country:
            signals.append(
                ProvenanceSignal(
                    id="ip_geo",
                    kind=SignalKind.INFRASTRUCTURE,
                    country=country,
                    weight=0.0,
                    source="country.is",
                    detail="Hosting/edge IP geography (infrastructure only).",
                    observed=ip,
                )
            )
        elif geo.get("error"):
            signals.append(
                ProvenanceSignal(
                    id="ip_geo_error",
                    kind=SignalKind.CONTEXT,
                    source="country.is",
                    detail="country.is lookup failed.",
                    observed=str(geo.get("error"))[:200],
                )
            )

    return signals
