"""Read-only authoritative DNS check: ask a domain's own nameservers directly.

Module responsibility:
    Walk DNS referrals from the root servers down to the zone that holds a hostname,
    then query every nameserver of that zone directly (no recursion). Compare with
    public recursive resolvers and this PC's resolver to say where a
    ``DNS_PROBE_FINISHED_NXDOMAIN`` / ``ERR_NAME_NOT_RESOLVED`` failure lives:
    the site's DNS hosting (lame delegation, unregistered name, missing record) or
    this client.

System placement:
    Called by ``dns_edge.diagnose_dns_edge`` when ``dns-edge-status --url`` is given.
    Pure classification (``classify_authoritative``) is separate from network I/O for
    fixture tests; the network path is injectable (``query``, ``resolve_ip``,
    ``system_resolve``).

Key invariants:
    * Read-only: sends DNS queries only; never changes adapter DNS, policy, or caches.
    * Minimal stdlib DNS client (UDP, IPv4, A queries) — no third-party dependency and
      no parsing of localized ``nslookup`` output.
    * A site-side verdict means no client fix (``FIX_ERR_NAME_NOT_RESOLVED``) can help.

Side effects:
    UDP/53 queries to root, TLD, and the domain's nameservers, plus 1.1.1.1 / 8.8.8.8,
    and one ``getaddrinfo`` through this PC's resolver.

Failure modes:
    Networks that block outbound UDP/53 except to the local resolver → no root reply →
    ``INCONCLUSIVE_DIRECT_DNS_BLOCKED``. DNSSEC validation is not checked.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
from collections.abc import Callable
from typing import Any

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

ROOT_SERVERS: tuple[tuple[str, str], ...] = (
    ("a.root-servers.net", "198.41.0.4"),
    ("c.root-servers.net", "192.33.4.12"),
    ("f.root-servers.net", "192.5.5.241"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
)
PUBLIC_RESOLVERS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
QUERY_TIMEOUT_S = 2.5
MAX_REFERRAL_HOPS = 8
MAX_SERVERS_PER_HOP = 3

_GOOD_STATUSES = {"authoritative", "nxdomain_authoritative", "referral"}
SITE_SIDE = {
    "NOT_DELEGATED_NXDOMAIN",
    "LAME_DELEGATION",
    "AUTHORITATIVE_UNREACHABLE",
    "NAME_NOT_IN_ZONE",
}

LIMITATIONS = [
    "Single A-record query per server over UDP/IPv4; DNSSEC validation is not checked.",
    "A snapshot: nameserver state can change minutes later (propagation, caching).",
    "Networks that only allow DNS to the local resolver make the direct check inconclusive.",
]

DnsResponse = dict[str, Any]
QueryFn = Callable[[str, str, bool], DnsResponse | None]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(qname: str, qtype: int = QTYPE_A, *, rd: bool, qid: int | None = None) -> bytes:
    """DNS query packet (one question, IN class)."""
    ident = random.randint(0, 0xFFFF) if qid is None else qid
    flags = 0x0100 if rd else 0x0000
    return (
        struct.pack(">HHHHHH", ident, flags, 1, 0, 0, 0)
        + _encode_name(qname)
        + struct.pack(">HH", qtype, 1)
    )


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None
    for _ in range(128):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        if length == 0:
            return ".".join(labels).lower(), end if end is not None else offset + 1
        labels.append(packet[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    raise ValueError("DNS name compression loop")


def parse_response(packet: bytes) -> DnsResponse:
    """Parse header flags, A answers, NS authority records, and A glue."""
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    offset = 12
    for _ in range(qd):
        _, offset = _read_name(packet, offset)
        offset += 4
    answers: list[str] = []
    cnames: list[str] = []
    authority_ns: list[list[str]] = []
    soa_zone: str | None = None
    glue: dict[str, str] = {}
    for index in range(an + ns + ar):
        owner, offset = _read_name(packet, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", packet[offset : offset + 10])
        offset += 10
        rdata_at = offset
        offset += rdlen
        section = "answer" if index < an else "authority" if index < an + ns else "additional"
        if rtype == QTYPE_A and rdlen == 4:
            ip = socket.inet_ntoa(packet[rdata_at:offset])
            if section == "answer":
                answers.append(ip)
            elif section == "additional":
                glue.setdefault(owner, ip)
        elif rtype == QTYPE_CNAME and section == "answer":
            cnames.append(_read_name(packet, rdata_at)[0])
        elif rtype == QTYPE_NS and section == "authority":
            authority_ns.append([owner, _read_name(packet, rdata_at)[0]])
        elif rtype == QTYPE_SOA and section == "authority":
            soa_zone = owner
    return {
        "id": ident,
        "rcode": flags & 0x000F,
        "aa": bool(flags & 0x0400),
        "truncated": bool(flags & 0x0200),
        "answers": answers,
        "cnames": cnames,
        "authority_ns": authority_ns,
        "soa_zone": soa_zone,
        "glue": glue,
    }


def udp_query(server_ip: str, qname: str, rd: bool) -> DnsResponse | None:
    """Send one A query; ``None`` on timeout/socket error/garbled reply."""
    packet = build_query(qname, QTYPE_A, rd=rd)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(QUERY_TIMEOUT_S)
            sock.sendto(packet, (server_ip, 53))
            for _ in range(3):
                data, _ = sock.recvfrom(4096)
                if data[:2] == packet[:2]:
                    return parse_response(data)
    except (OSError, ValueError, struct.error, IndexError):
        return None
    return None


def _system_ipv4(name: str) -> str | None:
    try:
        return str(socket.getaddrinfo(name, None, socket.AF_INET)[0][4][0])
    except (OSError, IndexError):
        return None


def system_resolve(host: str) -> dict[str, Any]:
    """Resolve through this PC's resolver (what the browser's OS path sees)."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
    except OSError as exc:
        return {"ok": False, "addresses": [], "error": str(exc)[:160]}
    return {"ok": True, "addresses": sorted({str(i[4][0]) for i in infos}), "error": None}


def _ask_any(
    servers: list[tuple[str, str]], host: str, query: QueryFn
) -> tuple[DnsResponse | None, str | None]:
    """First usable reply from up to ``MAX_SERVERS_PER_HOP`` servers (errors as fallback)."""
    fallback: tuple[DnsResponse | None, str | None] = (None, None)
    for name, ip in servers[:MAX_SERVERS_PER_HOP]:
        resp = query(ip, host, False)
        if resp is None:
            continue
        if resp["rcode"] in (RCODE_NOERROR, RCODE_NXDOMAIN):
            return resp, name
        fallback = (resp, name)
    return fallback


def walk_delegation(
    host: str,
    *,
    query: QueryFn,
    resolve_ip: Callable[[str], str | None],
) -> dict[str, Any]:
    """Follow referrals from the root to the deepest zone delegated for ``host``."""
    servers = list(ROOT_SERVERS)
    zone = "."
    chain: list[dict[str, Any]] = []
    stop = "max_hops"
    for _ in range(MAX_REFERRAL_HOPS):
        resp, used = _ask_any(servers, host, query)
        if resp is None:
            stop = "no_response"
            break
        if resp["rcode"] == RCODE_NXDOMAIN:
            stop = "nxdomain"
            break
        if resp["rcode"] != RCODE_NOERROR:
            stop = f"rcode_{RCODE_NAMES.get(resp['rcode'], resp['rcode'])}"
            break
        if resp["aa"] or resp["answers"] or resp["cnames"]:
            stop = "answer"
            break
        referral = [ns for owner, ns in resp["authority_ns"] if owner != zone]
        owner = resp["authority_ns"][0][0] if resp["authority_ns"] else None
        if not referral or not owner or not (host == owner or host.endswith("." + owner)):
            stop = "no_referral"
            break
        glue = resp["glue"]
        chain.append(
            {"zone": owner, "nameservers": referral, "glue": dict(glue), "referred_by": used}
        )
        zone = owner
        servers = [(ns, ip) for ns in referral if (ip := glue.get(ns) or resolve_ip(ns))]
        if not servers:
            stop = "nameservers_unresolvable"
            break
    return {"chain": chain, "stop": stop, "zone": zone}


def _probe_status(resp: DnsResponse | None) -> str:
    if resp is None:
        return "timeout"
    rcode = resp["rcode"]
    if rcode == RCODE_REFUSED:
        return "refused"
    if rcode == RCODE_SERVFAIL:
        return "servfail"
    if rcode == RCODE_NXDOMAIN:
        return "nxdomain_authoritative" if resp["aa"] else "not_authoritative"
    if rcode != RCODE_NOERROR:
        return f"rcode_{RCODE_NAMES.get(rcode, rcode)}"
    if resp["aa"]:
        return "authoritative"
    if resp["authority_ns"]:
        return "referral"
    return "not_authoritative"


def probe_nameservers(
    host: str,
    delegation: dict[str, Any],
    *,
    query: QueryFn,
    resolve_ip: Callable[[str], str | None],
) -> list[dict[str, Any]]:
    """Ask every nameserver of the delegated zone directly (recursion off)."""
    rows: list[dict[str, Any]] = []
    for ns in delegation["nameservers"]:
        ip = delegation["glue"].get(ns) or resolve_ip(ns)
        if ip is None:
            rows.append({"nameserver": ns, "ip": None, "status": "ns_unresolvable"})
            continue
        resp = query(ip, host, False)
        rows.append(
            {
                "nameserver": ns,
                "ip": ip,
                "status": _probe_status(resp),
                "rcode": RCODE_NAMES.get(resp["rcode"], resp["rcode"]) if resp else None,
                "answers": (resp or {}).get("answers") or [],
            }
        )
    return rows


def _resolver_row(server: str, resp: DnsResponse | None) -> dict[str, Any]:
    if resp is None:
        return {"resolver": server, "ok": False, "rcode": None, "answers": []}
    return {
        "resolver": server,
        "ok": resp["rcode"] == RCODE_NOERROR and bool(resp["answers"] or resp["cnames"]),
        "rcode": RCODE_NAMES.get(resp["rcode"], resp["rcode"]),
        "answers": resp["answers"],
    }


def _registry_nxdomain(walk: dict[str, Any]) -> bool:
    """NXDOMAIN came from the root or TLD servers (no delegation below the TLD)."""
    return walk["stop"] == "nxdomain" and len(walk["chain"]) <= 1


def classify_authoritative(
    host: str,
    walk: dict[str, Any],
    probes: list[dict[str, Any]],
    public: list[dict[str, Any]],
    system: dict[str, Any],
) -> dict[str, Any]:
    """Locate the DNS failure: site-side, client-side, resolver-side, or fine."""
    chain = walk["chain"]
    zone = chain[-1]["zone"] if chain else None
    names = ", ".join(r["nameserver"] for r in probes)
    statuses = [r["status"] for r in probes]
    good = [s for s in statuses if s in _GOOD_STATUSES]
    public_ok = any(r["ok"] for r in public)

    if not chain and walk["stop"] == "no_response":
        classification = "INCONCLUSIVE_DIRECT_DNS_BLOCKED"
        summary = (
            "No root server answered direct DNS queries; this network may only allow DNS "
            "through the local resolver, so the domain's own nameservers could not be checked."
        )
    elif _registry_nxdomain(walk):
        registry = walk["zone"] if walk["zone"] != "." else "the root zone"
        classification = "NOT_DELEGATED_NXDOMAIN"
        summary = (
            f"The registry for {registry} says {host} does not exist "
            "(unregistered, expired, or suspended domain)."
        )
    elif not probes:
        classification = "INCONCLUSIVE"
        summary = f"Could not find the nameservers for {host} (walk stopped: {walk['stop']})."
    elif not good:
        if all(s == "timeout" for s in statuses):
            classification = "AUTHORITATIVE_UNREACHABLE"
            summary = (
                f"{zone} is delegated to {len(probes)} nameservers ({names}), and none of "
                "them replied — the site's DNS servers are down or unreachable."
            )
        else:
            classification = "LAME_DELEGATION"
            summary = (
                f"{zone} is delegated to {len(probes)} nameservers ({names}), but they all "
                f"refuse or fail to answer for it ({', '.join(sorted(set(statuses)))}). The "
                "site's DNS hosting is broken (for example a deleted DNS zone)."
            )
            if all("awsdns-" in r["nameserver"] for r in probes):
                summary += (
                    " These are Amazon Route 53 servers: the hosted zone is missing, or its "
                    "NS set no longer matches the one registered for the domain."
                )
    elif len(good) < len(statuses):
        classification = "PARTIAL_LAME_DELEGATION"
        summary = (
            f"{len(statuses) - len(good)} of {len(statuses)} nameservers for {zone} fail "
            "to answer, so lookups fail intermittently depending on which one is asked."
        )
    elif all(s == "nxdomain_authoritative" for s in statuses):
        classification = "NAME_NOT_IN_ZONE"
        summary = (
            f"{zone}'s nameservers answer, but say {host} has no record — the site owner "
            "has not published this hostname."
        )
    elif not system["ok"] and public_ok:
        classification = "AUTHORITATIVE_OK_CLIENT_RESOLVER_FAILS"
        summary = (
            f"{host} resolves at its own nameservers and via public DNS, but not through "
            "this PC's resolver — a client-side DNS problem."
        )
    elif not public_ok and not system["ok"]:
        classification = "AUTHORITATIVE_OK_RESOLVERS_FAIL"
        summary = (
            f"{host}'s nameservers answer directly, yet public resolvers fail — often a "
            "broken DNSSEC signature on the site's side (not checked here)."
        )
    else:
        classification = "AUTHORITATIVE_OK"
        summary = f"{host} resolves correctly at its own nameservers and from this PC."

    if classification in SITE_SIDE or classification == "AUTHORITATIVE_OK_RESOLVERS_FAIL":
        verdict, client_fix_helps = "site_side", False
    elif classification == "PARTIAL_LAME_DELEGATION":
        verdict, client_fix_helps = "site_side_intermittent", False
    elif classification == "AUTHORITATIVE_OK_CLIENT_RESOLVER_FAILS":
        verdict, client_fix_helps = "client_side", True
    elif classification == "AUTHORITATIVE_OK":
        verdict, client_fix_helps = "dns_ok", None
    else:
        verdict, client_fix_helps = "inconclusive", None
    return {
        "classification": classification,
        "verdict": verdict,
        "client_fix_helps": client_fix_helps,
        "summary": summary,
        "zone": zone,
    }


def check_authoritative_dns(
    target: str,
    *,
    query: QueryFn | None = None,
    resolve_ip: Callable[[str], str | None] | None = None,
    system: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Ask ``target``'s own nameservers directly and locate any DNS failure.

    Args:
        target: URL or hostname (``https://example.com/x`` or ``example.com``).
        query: Injected ``(server_ip, qname, rd) -> response | None`` (tests).
        resolve_ip: Injected nameserver-hostname → IPv4 lookup (tests).
        system: Injected this-PC resolver (tests).

    Returns:
        ``host``, ``delegation_chain``, ``nameservers[]`` (per-server status),
        ``public_resolvers[]``, ``system_resolver``, ``classification``, ``verdict``,
        ``client_fix_helps``, ``summary``, ``limitations``.
    """
    host = _host_of(target)
    base = {"host": host, "limitations": list(LIMITATIONS)}
    if host is None:
        return {
            **base,
            "classification": "NOT_A_HOSTNAME",
            "verdict": "inconclusive",
            "client_fix_helps": None,
            "summary": f"{target!r} is an IP address or not a valid hostname.",
        }
    query_fn = query or udp_query
    resolve_fn = resolve_ip or _system_ipv4
    walk = walk_delegation(host, query=query_fn, resolve_ip=resolve_fn)
    delegation = walk["chain"][-1] if walk["chain"] else None
    probes = (
        probe_nameservers(host, delegation, query=query_fn, resolve_ip=resolve_fn)
        if delegation and not _registry_nxdomain(walk)
        else []
    )
    public = [_resolver_row(ip, query_fn(ip, host, True)) for ip in PUBLIC_RESOLVERS]
    system_row = (system or system_resolve)(host)
    verdict = classify_authoritative(host, walk, probes, public, system_row)
    return {
        **base,
        **verdict,
        "delegation_chain": [
            {k: v for k, v in hop.items() if k != "glue"} for hop in walk["chain"]
        ],
        "walk_stop": walk["stop"],
        "nameservers": probes,
        "public_resolvers": public,
        "system_resolver": system_row,
    }


def _host_of(target: str) -> str | None:
    raw = target.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    raw = raw.rsplit("@", 1)[-1]
    if raw.startswith("["):
        return None
    host = raw.split(":", 1)[0].strip(".").lower()
    if not host or "." not in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        _encode_name(host)
    except (ValueError, UnicodeError):
        return None
    return host
