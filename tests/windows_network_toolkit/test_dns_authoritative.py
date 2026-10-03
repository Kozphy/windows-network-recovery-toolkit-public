"""Tests for the authoritative-nameserver DNS check (fixture DNS world, no network)."""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from typing import Any

import pytest

from windows_network_toolkit.dns_authoritative import (
    PUBLIC_RESOLVERS,
    ROOT_SERVERS,
    _encode_name,
    _host_of,
    build_query,
    check_authoritative_dns,
    parse_response,
)
from windows_network_toolkit.dns_edge import diagnose_dns_edge

ROOT_IPS = {ip for _, ip in ROOT_SERVERS}
TLD_IP = "192.5.6.30"
NS_IPS = {"ns1.dns-host.test": "10.0.0.1", "ns2.dns-host.test": "10.0.0.2"}
SITE = "site.net"

Handler = Callable[[str, bool], dict[str, Any] | None]


def _resp(
    rcode: int = 0,
    *,
    aa: bool = False,
    answers: list[str] | None = None,
    authority_ns: list[list[str]] | None = None,
    glue: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": 1,
        "rcode": rcode,
        "aa": aa,
        "truncated": False,
        "answers": answers or [],
        "cnames": [],
        "authority_ns": authority_ns or [],
        "soa_zone": None,
        "glue": glue or {},
    }


def _world(
    *,
    tld: Handler | None = None,
    ns: dict[str, Handler] | None = None,
    public: Handler | None = None,
) -> Callable[[str, str, bool], dict[str, Any] | None]:
    """Fake DNS: root refers to ``net``, TLD refers ``site.net`` to two nameservers."""

    def root(_qname: str, _rd: bool) -> dict[str, Any]:
        return _resp(authority_ns=[["net", "a.gtld.test"]], glue={"a.gtld.test": TLD_IP})

    def default_tld(_qname: str, _rd: bool) -> dict[str, Any]:
        return _resp(authority_ns=[[SITE, name] for name in NS_IPS])

    handlers: dict[str, Handler] = {ip: root for ip in ROOT_IPS}
    handlers[TLD_IP] = tld or default_tld
    for name, ip in NS_IPS.items():
        handlers[ip] = (ns or {}).get(name, lambda _q, _rd: None)
    for ip in PUBLIC_RESOLVERS:
        handlers[ip] = public or (lambda _q, _rd: _resp(answers=["203.0.113.7"]))

    def query(server_ip: str, qname: str, rd: bool) -> dict[str, Any] | None:
        handler = handlers.get(server_ip)
        return handler(qname, rd) if handler else None

    return query


def _check(query: Callable[..., Any], *, system_ok: bool, target: str = SITE) -> dict[str, Any]:
    return check_authoritative_dns(
        target,
        query=query,
        resolve_ip=NS_IPS.get,
        system=lambda _h: {"ok": system_ok, "addresses": [], "error": None},
    )


def _refused(_q: str, _rd: bool) -> dict[str, Any]:
    return _resp(5)


def _answer(_q: str, _rd: bool) -> dict[str, Any]:
    return _resp(aa=True, answers=["203.0.113.7"])


def _servfail(_q: str, _rd: bool) -> dict[str, Any]:
    return _resp(2)


def test_lame_delegation_all_nameservers_refuse() -> None:
    query = _world(
        ns={name: _refused for name in NS_IPS},
        public=_servfail,
    )
    result = _check(query, system_ok=False, target="https://site.net/path?q=1")
    assert result["host"] == SITE
    assert result["classification"] == "LAME_DELEGATION"
    assert result["verdict"] == "site_side"
    assert result["client_fix_helps"] is False
    assert [r["status"] for r in result["nameservers"]] == ["refused", "refused"]
    assert result["delegation_chain"][-1]["zone"] == SITE
    assert "glue" not in result["delegation_chain"][0]
    assert result["limitations"]


def test_route53_hint_when_all_nameservers_are_awsdns() -> None:
    aws = {"ns-1.awsdns-01.com": "10.0.1.1", "ns-2.awsdns-02.net": "10.0.1.2"}

    def tld(_q: str, _rd: bool) -> dict[str, Any]:
        return _resp(authority_ns=[[SITE, name] for name in aws])

    base = _world(tld=tld, public=_servfail)

    def query(server_ip: str, qname: str, rd: bool) -> dict[str, Any] | None:
        return _resp(5) if server_ip in aws.values() else base(server_ip, qname, rd)

    result = check_authoritative_dns(
        SITE,
        query=query,
        resolve_ip=aws.get,
        system=lambda _h: {"ok": False, "addresses": [], "error": "x"},
    )
    assert result["classification"] == "LAME_DELEGATION"
    assert "Route 53" in result["summary"]


def test_unregistered_domain_nxdomain_from_tld() -> None:
    query = _world(tld=lambda _q, _rd: _resp(3), public=lambda _q, _rd: _resp(3))
    result = _check(query, system_ok=False)
    assert result["classification"] == "NOT_DELEGATED_NXDOMAIN"
    assert result["verdict"] == "site_side"
    assert result["nameservers"] == []
    assert "registry for net" in result["summary"]


def test_name_not_in_zone_nxdomain_from_domain_servers() -> None:
    nx = lambda _q, _rd: _resp(3, aa=True)  # noqa: E731
    query = _world(ns={name: nx for name in NS_IPS}, public=lambda _q, _rd: _resp(3))
    result = _check(query, system_ok=False, target="missing.site.net")
    assert result["classification"] == "NAME_NOT_IN_ZONE"
    assert result["verdict"] == "site_side"


def test_partial_lame_is_intermittent_site_side() -> None:
    query = _world(ns={"ns1.dns-host.test": _answer, "ns2.dns-host.test": _refused})
    result = _check(query, system_ok=True)
    assert result["classification"] == "PARTIAL_LAME_DELEGATION"
    assert result["verdict"] == "site_side_intermittent"
    assert result["client_fix_helps"] is False


def test_authoritative_ok_but_this_pc_fails_is_client_side() -> None:
    query = _world(ns={name: _answer for name in NS_IPS})
    result = _check(query, system_ok=False)
    assert result["classification"] == "AUTHORITATIVE_OK_CLIENT_RESOLVER_FAILS"
    assert result["verdict"] == "client_side"
    assert result["client_fix_helps"] is True


def test_authoritative_ok_everywhere() -> None:
    query = _world(ns={name: _answer for name in NS_IPS})
    result = _check(query, system_ok=True)
    assert result["classification"] == "AUTHORITATIVE_OK"
    assert result["verdict"] == "dns_ok"


def test_unreachable_nameservers() -> None:
    query = _world(public=_servfail)
    result = _check(query, system_ok=False)
    assert result["classification"] == "AUTHORITATIVE_UNREACHABLE"
    assert result["verdict"] == "site_side"


def test_direct_dns_blocked_is_inconclusive() -> None:
    result = check_authoritative_dns(
        SITE,
        query=lambda _ip, _q, _rd: None,
        resolve_ip=NS_IPS.get,
        system=lambda _h: {"ok": True, "addresses": ["203.0.113.7"], "error": None},
    )
    assert result["classification"] == "INCONCLUSIVE_DIRECT_DNS_BLOCKED"
    assert result["verdict"] == "inconclusive"
    assert result["client_fix_helps"] is None


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://WWW.Example.com:8443/a?b#c", "www.example.com"),
        ("user@example.org", "example.org"),
        ("example.com.", "example.com"),
        ("192.168.1.1", None),
        ("http://[2001:db8::1]/", None),
        ("localhost", None),
        ("", None),
        ("bad..name.com", None),
    ],
)
def test_host_of(target: str, expected: str | None) -> None:
    assert _host_of(target) == expected


def test_ip_target_returns_not_a_hostname() -> None:
    result = check_authoritative_dns("8.8.8.8", query=lambda *_a: None)
    assert result["classification"] == "NOT_A_HOSTNAME"
    assert result["verdict"] == "inconclusive"


def test_build_query_header_and_question() -> None:
    packet = build_query("example.com", rd=False, qid=0xABCD)
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    assert (ident, flags, qd, an, ns, ar) == (0xABCD, 0, 1, 0, 0, 0)
    assert packet[12:] == _encode_name("example.com") + struct.pack(">HH", 1, 1)
    assert struct.unpack(">H", build_query("a.b", rd=True, qid=1)[2:4])[0] == 0x0100


def test_parse_response_with_compression() -> None:
    question = _encode_name("www.example.com") + struct.pack(">HH", 1, 1)
    header = struct.pack(">HHHHHH", 0x1234, 0x8405, 1, 1, 1, 1)
    # Pointers: 0xC00C -> "www.example.com" at offset 12; 0xC010 -> "example.com".
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
    ns_rdata = b"\x03ns1\xc0\x10"
    authority = b"\xc0\x10" + struct.pack(">HHIH", 2, 1, 60, len(ns_rdata)) + ns_rdata
    glue = (
        _encode_name("ns1.example.com")
        + struct.pack(">HHIH", 1, 1, 60, 4)
        + socket.inet_aton("192.0.2.53")
    )
    parsed = parse_response(header + question + answer + authority + glue)
    assert parsed["id"] == 0x1234
    assert parsed["rcode"] == 5
    assert parsed["aa"] is True
    assert parsed["answers"] == ["93.184.216.34"]
    assert parsed["authority_ns"] == [["example.com", "ns1.example.com"]]
    assert parsed["glue"] == {"ns1.example.com": "192.0.2.53"}


def test_parse_response_rejects_compression_loop() -> None:
    header = struct.pack(">HHHHHH", 1, 0x8000, 1, 0, 0, 0)
    with pytest.raises(ValueError, match="loop"):
        parse_response(header + b"\xc0\x0c")


_WIFI = {
    "interface_alias": "Wi-Fi",
    "ipv4": "192.168.68.10",
    "gateway": "192.168.68.1",
    "dns_servers": ["1.1.1.1", "8.8.8.8"],
    "error": None,
}
_POLICY = {"dns_over_https_mode": "off", "builtin_dns_client_enabled": 0}
_RESOLVES = [{"host": "www.google.com", "ok": True, "addresses": ["1.2.3.4"], "error": None}]


def test_dns_edge_status_site_side_does_not_recommend_token_fix() -> None:
    query = _world(ns={name: _refused for name in NS_IPS}, public=_servfail)
    target = _check(query, system_ok=False)
    payload = diagnose_dns_edge(
        wifi=_WIFI,
        edge_policy=_POLICY,
        resolves=_RESOLVES,
        url="https://site.net/",
        authoritative=target,
    )
    assert payload["classification"] == "DNS_EDGE_OK"
    assert payload["target_verdict"] == "site_side"
    assert payload["authoritative_check"]["classification"] == "LAME_DELEGATION"
    step = payload["operator_next_step"]
    assert step["kind"] == "site_side_dns"
    assert step["command"] is None
    assert "not recommended" in step["reason"]
    assert any("DNSSEC" in item for item in payload["limitations"])


def test_dns_edge_status_client_side_points_to_gated_fix() -> None:
    query = _world(ns={name: _answer for name in NS_IPS})
    target = _check(query, system_ok=False)
    payload = diagnose_dns_edge(
        wifi=_WIFI,
        edge_policy=_POLICY,
        resolves=_RESOLVES,
        url=SITE,
        authoritative=target,
    )
    step = payload["operator_next_step"]
    assert step["kind"] == "dns_edge_fix_apply"
    assert "--confirm FIX_ERR_NAME_NOT_RESOLVED" in step["command"]


def test_dns_edge_status_without_url_has_no_target_fields() -> None:
    payload = diagnose_dns_edge(wifi=_WIFI, edge_policy=_POLICY, resolves=_RESOLVES)
    assert "authoritative_check" not in payload
    assert payload["operator_next_step"]["kind"] == "observe"
