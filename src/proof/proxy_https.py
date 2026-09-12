"""Localhost-proxy HTTPS causal contrast (curl with proxy vs `--noproxy '*'`).

Interprets :class:`~src.core.models.ProxyRegistrySnapshot` plus WinHTTP text and compares
explicit proxy routing against a no-proxy control fetch.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from typing import Any

from ..core.models import ParsedProxy
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.registry import read_proxy_registry
from .contracts import OutcomeLiteral, ProofCheck, ProofObservation, ProofResult, ProofStatus

_DEFAULT_TEST_URL = "https://www.google.com"
_CURL_DEADLINE_EXTRA = 8.0

_LISTEN_TAIL = re.compile(r":(\d{1,5})\s*$")
_LOCALHOST_NEEDLE = re.compile(
    r"(?:127\.(?:\d{1,3}\.){2}\d{1,3}|localhost|\[::1\])(?::(\d{1,5}))?",
    re.IGNORECASE,
)


def _run_cmd(
    argv: list[str],
    *,
    subprocess_run: Callable[..., Any],
    timeout: float,
) -> tuple[int, str]:
    try:
        proc = subprocess_run(
            argv,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return int(proc.returncode), out.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _winhttp_text(*, subprocess_run: Callable[..., Any], timeout: float) -> tuple[int, str]:
    return _run_cmd(
        ["netsh", "winhttp", "show", "proxy"],
        subprocess_run=subprocess_run,
        timeout=timeout,
    )


def _winhttp_hints_localhost(text: str) -> tuple[bool, int | None]:
    """Coarse loopback hints from ``netsh winhttp show proxy`` output."""
    if "direct access" in text.lower():
        return False, None
    lowered = text.lower()
    if "proxy" not in lowered:
        return False, None
    m_ports: list[int] = []
    hyphen_only = False
    for m in _LOCALHOST_NEEDLE.finditer(text):
        if m.group(1) is None:
            hyphen_only = True
            continue
        try:
            po = int(m.group(1))
        except (TypeError, ValueError):
            continue
        if 1 <= po <= 65535:
            m_ports.append(po)
    if m_ports:
        return True, m_ports[0]
    return hyphen_only or ("127." in lowered and "proxy" in lowered), None


def _listening_on_port_windows(output: str, port: int) -> bool | None:
    if not output.strip():
        return None
    token = str(port)
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        upper = line.upper()
        if "LISTENING" not in upper and "LISTEN" not in upper:
            continue
        loc = parts[1]
        m = _LISTEN_TAIL.search(loc)
        if not m or m.group(1) != token:
            continue
        loc_lower = loc.lower()
        if loc_lower.startswith(("127.", "0.0.0.0:", "[::]", "[::1")):
            return True
        if loc_lower.startswith(":::"):
            return True
        if "::" in loc_lower and "]:" in loc and token in loc:
            return True
    return False


def _effective_proxy_listen_port(parsed: ParsedProxy) -> int | None:
    if not parsed.is_localhost_proxy:
        return None
    if parsed.proxy_mode == "socks_localhost" and parsed.socks_port is not None:
        return int(parsed.socks_port)
    for p in (parsed.https_localhost_port, parsed.http_localhost_port, parsed.localhost_port):
        if p is not None:
            return int(p)
    return None


def _curl_proxy_url(parsed: ParsedProxy) -> tuple[str | None, str]:
    """Return curl ``-x`` URL for localhost proxy routing, plus scheme note."""
    if not parsed.is_localhost_proxy:
        return None, "no_loopback_segment"
    if parsed.proxy_mode == "socks_localhost" and parsed.socks_port:
        return f"socks5h://127.0.0.1:{parsed.socks_port}", "socks5h"
    port = parsed.https_localhost_port or parsed.http_localhost_port or parsed.localhost_port
    if port is None:
        return None, "no_port_for_http_connect"
    return f"http://127.0.0.1:{port}", "http_connect"


def _port_from_proxy_url(url: str | None) -> int | None:
    if not url:
        return None
    idx = url.rfind(":")
    if idx <= 0 or idx >= len(url) - 1:
        return None
    try:
        return int(url[idx + 1 :])
    except ValueError:
        return None


def _curl_https_probe(
    base_url: str,
    *,
    proxy_url: str | None,
    noproxy_all: bool,
    subprocess_run: Callable[..., Any],
    timeout: float,
) -> tuple[int, str, list[str]]:
    argv: list[str] = [
        "curl",
        "-sS",
        "-o",
        "NUL",
        "-w",
        "%{http_code}",
        "-L",
        "--max-time",
        str(timeout),
    ]
    insert_at = 1
    if noproxy_all:
        argv.insert(insert_at, "--noproxy")
        argv.insert(insert_at + 1, "*")
        insert_at += 2
    elif proxy_url:
        argv.insert(insert_at, "-x")
        argv.insert(insert_at + 1, proxy_url)
        insert_at += 2
    argv.extend([base_url])
    code, out = _run_cmd(argv, subprocess_run=subprocess_run, timeout=timeout + _CURL_DEADLINE_EXTRA)
    return code, out, argv


def _interpret_curl_https_ok(returncode: int, written_code_field: str) -> bool:
    if returncode != 0:
        return False
    s = written_code_field.strip()
    if not s.isdigit():
        return False
    return int(s) > 0 and int(s) < 600


class LocalhostProxyHttpsProof(ProofCheck):
    """Causal HTTPS contrast for traffic via configured localhost proxy vs bypass."""

    _DEFAULT_HYPOTHESIS = (
        "Traffic is routed through a localhost proxy (127.0.0.1:<port>) and that path affects HTTPS reachability "
        "versus the same URL fetched with `curl --noproxy` (control)."
    )

    @property
    def proof_id(self) -> str:
        """Proof id.
        
        Args:
            None.
        
        Returns:
            The str result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return "localhost_proxy_https_contrast"

    @property
    def hypothesis_description(self) -> str:
        """Hypothesis description.
        
        Args:
            None.
        
        Returns:
            The str result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self._DEFAULT_HYPOTHESIS

    def execute(
        self,
        *,
        test_url: str = _DEFAULT_TEST_URL,
        subprocess_run: Callable[..., Any] = subprocess.run,
        reg_timeout: float = 18.0,
        net_timeout: float = 18.0,
        curl_timeout: float = 12.0,
        **_kwargs: Any,
    ) -> ProofResult:
        """Execute.
        
        Args:
            test_url: The test url value supplied by the caller.
            subprocess_run: The subprocess run value supplied by the caller.
            reg_timeout: The reg timeout value supplied by the caller.
            net_timeout: The net timeout value supplied by the caller.
            curl_timeout: The curl timeout value supplied by the caller.
            **_kwargs: The kwargs value supplied by the caller.
        
        Returns:
            The ProofResult result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return run_localhost_proxy_https_proof(
            test_url=test_url,
            subprocess_run=subprocess_run,
            reg_timeout=reg_timeout,
            net_timeout=net_timeout,
            curl_timeout=curl_timeout,
        )


def run_localhost_proxy_https_proof(
    *,
    test_url: str = _DEFAULT_TEST_URL,
    subprocess_run: Callable[..., Any] = subprocess.run,
    reg_timeout: float = 18.0,
    net_timeout: float = 18.0,
    curl_timeout: float = 12.0,
    hypothesis: str | None = None,
) -> ProofResult:
    """Run HTTPS contrast proof (read-only)."""
    hypo = hypothesis or LocalhostProxyHttpsProof._DEFAULT_HYPOTHESIS
    obs: list[ProofObservation] = []
    evidence: dict[str, Any] = {}

    def add(step_id: str, label: str, outcome: OutcomeLiteral, detail: str) -> None:
        obs.append(ProofObservation(step_id=step_id, label=label, outcome=outcome, detail=detail))

    reg = read_proxy_registry(run=subprocess_run, query_timeout=reg_timeout)
    parsed = parse_proxy_server(reg.proxy_server)
    reg_enabled = reg.proxy_enable == 1

    wininet_active_localhost = bool(reg_enabled and parsed.is_localhost_proxy)
    proxy_url_eff, curl_scheme = _curl_proxy_url(parsed) if wininet_active_localhost else (None, "wininet_inactive")
    if not wininet_active_localhost:
        proxy_url_eff = None

    evidence["proxy_registry_snapshot"] = reg.to_dict()
    evidence["parsed_proxy_server"] = parsed.to_dict()

    add(
        "wininet_registry",
        "Detect WinINET proxy (HKCU registry)",
        "pass",
        (
            f"ProxyEnable={reg.proxy_enable!r}; ProxyServer parsed mode={parsed.proxy_mode}; "
            f"active_localhost={wininet_active_localhost}."
        ),
    )

    wh_code, wh_out = _winhttp_text(subprocess_run=subprocess_run, timeout=net_timeout)
    wh_localhost, wh_port = _winhttp_hints_localhost(wh_out) if wh_code == 0 else (False, None)
    evidence["winhttp_show_proxy"] = {"exit_code": wh_code, "output_excerpt": wh_out[:2400]}

    if wh_code == 0:
        add(
            "winhttp_detect",
            "Detect WinHTTP proxy (netsh winhttp)",
            "pass",
            f"loopback_hint={wh_localhost} parsed_port={wh_port}.",
        )
    else:
        add(
            "winhttp_detect",
            "Detect WinHTTP proxy (netsh winhttp)",
            "error",
            wh_out[:500] if wh_out else f"netsh failed code={wh_code}",
        )

    localhost_hint_anywhere = wininet_active_localhost or bool(wh_localhost)
    if proxy_url_eff is None and wh_localhost and wh_port is not None:
        proxy_url_eff = f"http://127.0.0.1:{wh_port}"
        curl_scheme = "http_connect_winhttp_fallback"

    add(
        "localhost_proxy_detection",
        "Detect localhost proxy (WinINET active segment or WinHTTP loopback hints)",
        "pass"
        if localhost_hint_anywhere
        else ("fail" if parsed.is_missing or parsed.is_malformed else "skipped"),
        (
            "Active WinINET localhost proxy."
            if wininet_active_localhost
            else (
                "WinHTTP shows loopback proxy hint."
                if wh_localhost
                else "No active WinINET localhost segment and no WinHTTP loopback hint."
            )
        ),
    )

    proof_listen_port = (
        _effective_proxy_listen_port(parsed) if wininet_active_localhost else None
    ) or wh_port
    if proof_listen_port is None:
        proof_listen_port = _port_from_proxy_url(proxy_url_eff)

    evidence["routing_summary"] = {
        "wininet_active_localhost": wininet_active_localhost,
        "winhttp_loopback_hint": wh_localhost,
        "effective_curl_proxy_url": proxy_url_eff,
        "effective_listen_probe_port": proof_listen_port,
        "curl_scheme": curl_scheme,
    }

    if proxy_url_eff is None:
        return ProofResult(
            proof_id="localhost_proxy_https_contrast",
            status=ProofStatus.INCONCLUSIVE,
            hypothesis=hypo,
            summary=(
                "INCONCLUSIVE: Could not derive an explicit localhost proxy URL for curl `-x` "
                "(PAC/AutoDetect-only, malformed ProxyServer, or WinHTTP lacked an extractable port)."
            ),
            observations=tuple(obs),
            evidence=evidence,
        )

    nc, ns_out = _run_cmd(["netstat", "-an"], subprocess_run=subprocess_run, timeout=net_timeout)
    listen_ok = None if nc != 0 or proof_listen_port is None else _listening_on_port_windows(ns_out, proof_listen_port)

    evidence["netstat_listen"] = {
        "exit_code": nc,
        "port_probed": proof_listen_port,
        "listening_best_effort": listen_ok,
    }
    if proof_listen_port is None:
        add(
            "port_listening",
            "Check localhost proxy TCP port is LISTENING (netstat)",
            "skipped",
            "Listen port unresolved after merge.",
        )
    elif nc != 0:
        add(
            "port_listening",
            "Check localhost proxy TCP port is LISTENING (netstat)",
            "error",
            f"netstat exited {nc}: {ns_out[:400]}",
        )
    elif listen_ok is True:
        add(
            "port_listening",
            "Check localhost proxy TCP port is LISTENING (netstat)",
            "pass",
            f"LISTEN-ish binding found for port {proof_listen_port}.",
        )
    elif listen_ok is False:
        add(
            "port_listening",
            "Check localhost proxy TCP port is LISTENING (netstat)",
            "fail",
            f"No LISTEN line matched for port {proof_listen_port} (non-fatal to HTTPS contrast).",
        )
    else:
        add(
            "port_listening",
            "Check localhost proxy TCP port is LISTENING (netstat)",
            "skipped",
            "Empty/unparseable netstat body.",
        )

    curl_v_code, curl_v_out = _run_cmd(
        ["curl", "--version"],
        subprocess_run=subprocess_run,
        timeout=12.0,
    )
    if curl_v_code != 0:
        add(
            "curl_available",
            "Verify curl is available",
            "fail",
            curl_v_out or "curl missing or unreachable on PATH.",
        )
        return ProofResult(
            proof_id="localhost_proxy_https_contrast",
            status=ProofStatus.INCONCLUSIVE,
            hypothesis=hypo,
            summary="INCONCLUSIVE: curl not available — cannot perform HTTPS causal contrast.",
            observations=tuple(obs),
            evidence=evidence | {"curl_version_probe_excerpt": curl_v_out[:400]},
        )
    add("curl_available", "Verify curl is available", "pass", curl_v_out.splitlines()[0][:200] if curl_v_out else "ok")

    code_with, out_with, argv_with = _curl_https_probe(
        test_url,
        proxy_url=proxy_url_eff,
        noproxy_all=False,
        subprocess_run=subprocess_run,
        timeout=curl_timeout,
    )
    ok_with = _interpret_curl_https_ok(code_with, out_with)
    evidence["https_via_explicit_proxy"] = {
        "exit_code": code_with,
        "http_code_field": out_with[:32],
        "argv": argv_with,
        "interpreted_ok": ok_with,
    }
    add(
        "https_with_proxy",
        "Test HTTPS with explicit localhost proxy (`curl -x …`)",
        "pass" if ok_with else "fail",
        f"exit={code_with} http_code_field={out_with.strip()!r}",
    )

    code_no, out_no, argv_no = _curl_https_probe(
        test_url,
        proxy_url=None,
        noproxy_all=True,
        subprocess_run=subprocess_run,
        timeout=curl_timeout,
    )
    ok_no = _interpret_curl_https_ok(code_no, out_no)
    evidence["https_bypass_proxy"] = {
        "exit_code": code_no,
        "http_code_field": out_no[:32],
        "argv": argv_no,
        "interpreted_ok": ok_no,
    }
    add(
        "https_bypass_proxy",
        "Test HTTPS bypassing env proxies (`curl --noproxy '*'`)",
        "pass" if ok_no else "fail",
        f"exit={code_no} http_code_field={out_no.strip()!r}",
    )

    if not ok_with and ok_no:
        status = ProofStatus.CONFIRMED
        summary = (
            "CONFIRMED: HTTPS fails via explicit localhost proxy path but succeeds via `--noproxy` bypass."
        )
    elif ok_with and ok_no:
        status = ProofStatus.REJECTED
        summary = (
            "REJECTED: Both paths succeed — this localhost proxy does not block this HTTPS probe."
        )
    elif ok_with and not ok_no:
        status = ProofStatus.INCONCLUSIVE
        summary = (
            "INCONCLUSIVE: HTTPS succeeds via explicit proxy yet bypass fails "
            "(check URL redirects, interception, curl defaults)."
        )
    else:
        status = ProofStatus.INCONCLUSIVE
        summary = (
            "INCONCLUSIVE: HTTPS fails both with localhost proxy routing and bypass — "
            "likely broader outage/TLS/filtering unrelated to localhost proxy differential."
        )

    evidence["comparison"] = {"via_proxy_ok": ok_with, "bypass_ok": ok_no}

    return ProofResult(
        proof_id="localhost_proxy_https_contrast",
        status=status,
        hypothesis=hypo,
        summary=summary,
        observations=tuple(obs),
        evidence=evidence,
    )
