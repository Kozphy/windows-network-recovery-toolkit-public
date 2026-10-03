"""Tests for unified why-broken synthesis (fixture inject, no live probes)."""

from __future__ import annotations

from windows_network_toolkit.why_broken import investigate_why_broken, synthesize_why_broken


def test_synthesize_prefers_dead_proxy_over_ipv6() -> None:
    result = synthesize_why_broken(
        proxy={
            "classification": "DEAD_LOCALHOST_PROXY",
            "classification_result": {"reasoning": "localhost proxy enabled, no listener"},
        },
        dns={"classification": "DNS_EDGE_OK", "classification_result": {"reasoning": "ok"}},
        ipv6={
            "path": {
                "classification": "IPV6_PATH_BLACKHOLE",
                "prefer_ipv4_bit_set": False,
                "classification_result": {"reasoning": "ipv4 ok ipv6 fail"},
            }
        },
    )
    assert result["primary_hypothesis"]["id"] == "proxy"
    assert result["attack_attribution"]["claimed"] is False
    assert "proxy-disable" in (result["operator_next_step"].get("command") or "")


def test_synthesize_ipv6_blackhole_when_proxy_clean() -> None:
    result = synthesize_why_broken(
        proxy={
            "classification": "NO_PROXY",
            "classification_result": {"reasoning": "proxy off"},
        },
        dns={"classification": "DNS_EDGE_OK", "classification_result": {"reasoning": "ok"}},
        ipv6={
            "path": {
                "classification": "IPV6_PATH_BLACKHOLE",
                "prefer_ipv4_bit_set": True,
                "classification_result": {"reasoning": "blackhole"},
            }
        },
        url_probe={
            "url": "https://example.com/",
            "host": "example.com",
            "ipv4": {"ok": True},
            "ipv6": {"ok": False},
        },
    )
    assert result["primary_hypothesis"]["id"] == "ipv6_path"
    assert (
        "prefer-IPv4" in result["primary_hypothesis"]["summary"]
        or "Prefer-IPv4" in result["primary_hypothesis"]["summary"]
    )
    assert (
        "Happy Eyeballs" in result["coding_vs_browser"]
        or "dual-stack" in result["coding_vs_browser"]
    )


def test_synthesize_dns_when_resolve_failed() -> None:
    result = synthesize_why_broken(
        proxy={"classification": "NO_PROXY"},
        dns={
            "classification": "DNS_RESOLVE_FAILED",
            "classification_result": {"reasoning": "no probes resolved"},
        },
        ipv6={"path": {"classification": "IPV6_PATH_OK", "prefer_ipv4_bit_set": False}},
    )
    assert result["primary_hypothesis"]["id"] == "dns_edge"
    assert "dns-edge-fix" in (result["operator_next_step"].get("command") or "")


def test_investigate_injected_no_live() -> None:
    payload = investigate_why_broken(
        url="https://example.com/",
        proxy={"classification": "NO_PROXY"},
        dns={"classification": "DNS_EDGE_OK"},
        ipv6={
            "path": {
                "classification": "IPV6_PATH_BLACKHOLE",
                "prefer_ipv4_bit_set": False,
            }
        },
        url_probe={
            "url": "https://example.com/",
            "host": "example.com",
            "ipv4": {"ok": True},
            "ipv6": {"ok": False},
        },
    )
    assert payload["command"] == "why-broken"
    assert payload["primary_hypothesis"]["id"] == "ipv6_path"
    assert payload["attack_attribution"]["claimed"] is False


def test_cli_why_broken_handler_exists() -> None:
    from windows_network_toolkit import cli as cli_mod

    assert callable(cli_mod.cmd_why_broken)
