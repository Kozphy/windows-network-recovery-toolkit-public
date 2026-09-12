"""Read-only proxy path proof — direct vs proxied vs bypass checks.

Does not mutate registry, disable proxy, or kill processes.
"""

from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

FailureMode = Literal[
    "none",
    "direct_blocked",
    "proxy_broken",
    "bypass_blocked",
    "dns_failure",
    "unknown",
]


@dataclass
class ProxyPathProof:
    """Network path evidence for browser/proxy troubleshooting."""

    direct_path_ok: bool | None
    proxied_path_ok: bool | None
    bypass_path_ok: bool | None
    failure_mode: FailureMode
    evidence_summary: str
    dns_ok: bool | None = None
    tls_ok: bool | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "direct_path_ok": self.direct_path_ok,
            "proxied_path_ok": self.proxied_path_ok,
            "bypass_path_ok": self.bypass_path_ok,
            "failure_mode": self.failure_mode,
            "evidence_summary": self.evidence_summary,
            "dns_ok": self.dns_ok,
            "tls_ok": self.tls_ok,
            "notes": list(self.notes),
        }


def _from_fixture(path: Path) -> ProxyPathProof:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "proxy_path" in data:
        data = data["proxy_path"]
    return ProxyPathProof(
        direct_path_ok=data.get("direct_path_ok"),
        proxied_path_ok=data.get("proxied_path_ok"),
        bypass_path_ok=data.get("bypass_path_ok"),
        failure_mode=data.get("failure_mode") or "unknown",
        evidence_summary=str(data.get("evidence_summary") or ""),
        dns_ok=data.get("dns_ok"),
        tls_ok=data.get("tls_ok"),
        notes=list(data.get("notes") or []),
    )


def _infer_failure(
    *,
    direct: bool | None,
    proxied: bool | None,
    bypass: bool | None,
) -> FailureMode:
    if proxied is False and bypass is True:
        return "proxy_broken"
    if direct is False:
        return "direct_blocked"
    if bypass is False:
        return "bypass_blocked"
    if direct is False and proxied is False:
        return "dns_failure"
    return "none" if proxied is not False else "unknown"


def collect_proxy_path_proof(
    *,
    proxy_server: str | None,
    proxy_enabled: bool | None,
    run: Callable[..., Any] = subprocess.run,
    fixture_path: Path | None = None,
    test_url: str = "https://www.google.com",
) -> ProxyPathProof:
    """Run safe read-only path checks or load fixture results.

    Args:
        proxy_server: Current ProxyServer string.
        proxy_enabled: ProxyEnable flag.
        run: Subprocess runner (curl probes when not in fixture mode).
        fixture_path: CI fixture override.
        test_url: HTTPS probe target.

    Returns:
        Path proof summary without mutating system state.
    """
    if fixture_path is not None and fixture_path.is_file():
        return _from_fixture(fixture_path)

    notes: list[str] = []
    direct_ok: bool | None = None
    proxied_ok: bool | None = None
    bypass_ok: bool | None = None
    dns_ok: bool | None = None

    if not proxy_enabled:
        return ProxyPathProof(
            direct_path_ok=True,
            proxied_path_ok=None,
            bypass_path_ok=True,
            failure_mode="none",
            evidence_summary="Proxy disabled — proxied path not applicable.",
            notes=["proxy_enable=0"],
        )

    try:
        host = test_url.split("://", 1)[-1].split("/", 1)[0]
        try:
            socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            dns_ok = True
        except OSError:
            dns_ok = False
            notes.append(f"dns_resolve_failed:{host}")

        from ..proof.proxy_https import _curl_https_probe, _curl_proxy_url, _interpret_curl_https_ok

        code_d, out_d, _ = _curl_https_probe(test_url, subprocess_run=run, timeout=12.0)
        direct_ok = _interpret_curl_https_ok(code_d, out_d)
        code_b, out_b, _ = _curl_https_probe(
            test_url,
            subprocess_run=run,
            timeout=12.0,
            extra_args=["--noproxy", "*"],
        )
        bypass_ok = _interpret_curl_https_ok(code_b, out_b)
        if proxy_server:
            proxy_url = _curl_proxy_url(proxy_server)
            code_p, out_p, _ = _curl_https_probe(
                test_url,
                subprocess_run=run,
                timeout=12.0,
                extra_args=["--proxy", proxy_url],
            )
            proxied_ok = _interpret_curl_https_ok(code_p, out_p)
        else:
            proxied_ok = None
            notes.append("proxy_server empty")
    except Exception as exc:
        notes.append(f"path_probe_skipped: {exc}")
        direct_ok = proxied_ok = bypass_ok = None

    if dns_ok is False:
        failure_mode: FailureMode = "dns_failure"
    else:
        failure_mode = _infer_failure(direct=direct_ok, proxied=proxied_ok, bypass=bypass_ok)
    failure = failure_mode
    summary_parts = []
    if proxied_ok is False and bypass_ok is True:
        summary_parts.append("Browser path fails through configured localhost proxy but direct bypass works.")
    elif proxied_ok is True:
        summary_parts.append("Proxied HTTPS path succeeded.")
    else:
        summary_parts.append("Path contrast inconclusive or not run.")
    return ProxyPathProof(
        direct_path_ok=direct_ok,
        proxied_path_ok=proxied_ok,
        bypass_path_ok=bypass_ok,
        failure_mode=failure,
        evidence_summary=" ".join(summary_parts),
        dns_ok=dns_ok,
        notes=notes,
    )
