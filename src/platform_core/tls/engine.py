"""TLS / MITM Evidence Engine — direct vs proxied certificate contrast."""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from src.platform_core.attribution.collector import collect_proxy_state

from .models import MitmRiskLevel, TlsCertificateSnapshot, TlsProofResult
from .root_store import audit_root_store


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_openssl_text(text: str, *, path: str, error: str) -> TlsCertificateSnapshot:
    subj = ""
    iss = ""
    m = re.search(r"subject:\s*(.+)", text, re.I)
    if m:
        subj = m.group(1).strip()
    m = re.search(r"issuer:\s*(.+)", text, re.I)
    if m:
        iss = m.group(1).strip()
    fp = ""
    m = re.search(r"SHA256 Fingerprint=([A-F0-9:]+)", text, re.I)
    if m:
        fp = m.group(1).replace(":", "").lower()
    return TlsCertificateSnapshot(
        path=path,
        subject=subj,
        issuer=iss,
        fingerprint_sha256=fp,
        raw_error=error,
    )


def _fetch_cert_openssl(host: str, port: int, *, proxy: str | None = None) -> TlsCertificateSnapshot:
    path = "proxied" if proxy else "direct"
    try:
        if proxy:
            argv = [
                "curl", "-sS", "--proxy", proxy, "-v",
                f"https://{host}:{port}/",
                "--max-time", "15",
            ]
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=20.0)
            stderr = proc.stderr or ""
            return _parse_openssl_text(stderr, path=path, error="" if proc.returncode == 0 else stderr[:200])

        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                sha = hashlib.sha256(cert_bin).hexdigest() if cert_bin else ""
                san: list[str] = []
                for typ, val in cert.get("subjectAltName", ()):
                    if typ == "DNS":
                        san.append(val)
                subj = ", ".join("=".join(x) for x in cert.get("subject", ()))
                iss = ", ".join("=".join(x) for x in cert.get("issuer", ()))
                return TlsCertificateSnapshot(
                    path=path,
                    subject=subj,
                    issuer=iss,
                    san=san,
                    not_before=str(cert.get("notBefore", "")),
                    not_after=str(cert.get("notAfter", "")),
                    serial_number=str(cert.get("serialNumber", "")),
                    fingerprint_sha256=sha,
                )
    except Exception as exc:
        return TlsCertificateSnapshot(path=path, raw_error=str(exc))


def _compare_certs(direct: TlsCertificateSnapshot, proxied: TlsCertificateSnapshot) -> tuple[bool, list[str]]:
    mismatches: list[str] = []
    if direct.fingerprint_sha256 and proxied.fingerprint_sha256:
        if direct.fingerprint_sha256 != proxied.fingerprint_sha256:
            mismatches.append("fingerprint_sha256")
    if direct.issuer and proxied.issuer and direct.issuer != proxied.issuer:
        mismatches.append("issuer")
    if direct.subject and proxied.subject and direct.subject != proxied.subject:
        mismatches.append("subject")
    if direct.serial_number and proxied.serial_number and direct.serial_number != proxied.serial_number:
        mismatches.append("serial_number")
    return bool(mismatches), mismatches


def _classify_mitm(
    *,
    mismatch: bool,
    suspicious_roots: list,
    proxy_enabled: bool,
) -> MitmRiskLevel:
    if mismatch and proxy_enabled:
        return MitmRiskLevel.HIGH
    if suspicious_roots:
        return MitmRiskLevel.MEDIUM
    if mismatch:
        return MitmRiskLevel.MEDIUM
    return MitmRiskLevel.LOW


def run_tls_proof(
    url: str,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 20.0,
    inject: dict[str, Any] | None = None,
    inject_roots: list[dict[str, Any]] | None = None,
) -> TlsProofResult:
    """Capture TLS certificates on direct and proxied paths; compare and audit root store."""
    if inject:
        return TlsProofResult.model_validate(inject)

    run_fn = run or subprocess.run
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or url
    port = parsed.port or 443

    proxy_state = collect_proxy_state(run=run_fn, timeout=timeout)
    proxy_server = proxy_state.wininet_proxy_server if proxy_state.wininet_proxy_enable == 1 else None

    direct = _fetch_cert_openssl(host, port)
    proxied: TlsCertificateSnapshot | None = None
    if proxy_server:
        proxied = _fetch_cert_openssl(host, port, proxy=proxy_server)

    mismatch = False
    mismatch_fields: list[str] = []
    if proxied:
        mismatch, mismatch_fields = _compare_certs(direct, proxied)

    roots = audit_root_store(run=run_fn, inject=inject_roots)
    suspicious = [r for r in roots if r.suspicious]

    mitm = _classify_mitm(
        mismatch=mismatch,
        suspicious_roots=suspicious,
        proxy_enabled=bool(proxy_server),
    )

    evidence = [{"type": "direct_certificate", "data": direct.model_dump()}]
    if proxied:
        evidence.append({"type": "proxied_certificate", "data": proxied.model_dump()})
    if mismatch_fields:
        evidence.append({"type": "certificate_mismatch", "fields": mismatch_fields})

    limitations = [
        "Certificate contrast indicates path difference — not definitive MITM without writer proof.",
        "Corporate TLS inspection may legitimately present different issuer chains.",
        "Root store audit is heuristic keyword matching — not a trust verdict.",
    ]

    return TlsProofResult(
        proof_id=f"tls-{uuid.uuid4().hex[:12]}",
        timestamp_utc=_now(),
        target_url=url,
        direct_cert=direct,
        proxied_cert=proxied,
        certificate_mismatch=mismatch,
        mismatch_fields=mismatch_fields,
        mitm_risk_level=mitm,
        root_ca_observations=roots[:50],
        suspicious_roots=suspicious,
        evidence=evidence,
        limitations=limitations,
    )
