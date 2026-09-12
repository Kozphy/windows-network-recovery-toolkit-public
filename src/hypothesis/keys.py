"""Canonical v2 hypothesis string literals referenced by ranking and audits."""

from __future__ import annotations

from typing import Literal

HypothesisKey = Literal[
    "unexpected_user_proxy",
    "local_proxy_hijack",
    "browser_proxy_path_issue",
    "localhost_proxy_owner_suspicious",
    "socket_exhaustion",
    "dns_resolution_issue",
    "tls_path_issue",
    "winhttp_proxy_issue",
    "winsock_corruption_possible",
    "isp_router_path_issue",
]


ALL_HYPOTHESES: tuple[HypothesisKey, ...] = (
    "unexpected_user_proxy",
    "local_proxy_hijack",
    "browser_proxy_path_issue",
    "localhost_proxy_owner_suspicious",
    "socket_exhaustion",
    "dns_resolution_issue",
    "tls_path_issue",
    "winhttp_proxy_issue",
    "winsock_corruption_possible",
    "isp_router_path_issue",
)
