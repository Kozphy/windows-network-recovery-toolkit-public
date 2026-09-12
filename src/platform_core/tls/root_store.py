"""Windows root certificate store audit — read-only."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .models import RootCaObservation

_SUSPICIOUS_ISSUER = re.compile(
    r"(mitm|proxy|debug|test|fake|charles|fiddler|burp|mitmproxy|superfish|eavesdrop)",
    re.I,
)


def _parse_cert_rows(ps_output: str, *, store: str) -> list[RootCaObservation]:
    rows: list[RootCaObservation] = []
    for line in ps_output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            continue
        subject, issuer, thumb, not_after = parts[0], parts[1], parts[2], parts[3]
        suspicious = bool(_SUSPICIOUS_ISSUER.search(subject) or _SUSPICIOUS_ISSUER.search(issuer))
        reason = ""
        if suspicious:
            reason = "Issuer or subject matches suspicious proxy/MITM keyword heuristics."
        rows.append(
            RootCaObservation(
                subject=subject,
                issuer=issuer,
                thumbprint=thumb,
                not_after=not_after,
                store=store,
                suspicious=suspicious,
                suspicion_reason=reason,
            )
        )
    return rows


def audit_root_store(
    *,
    run: Callable[..., Any] | None = None,
    inject: list[dict[str, Any]] | None = None,
    recently_added_days: int = 30,
) -> list[RootCaObservation]:
    """Audit LocalMachine and CurrentUser Root stores for suspicious CAs."""
    if inject is not None:
        return [RootCaObservation.model_validate(row) for row in inject]

    run_fn = run or subprocess.run
    ps = (
        "$stores=@('Cert:\\LocalMachine\\Root','Cert:\\CurrentUser\\Root');"
        "foreach($s in $stores){"
        "Get-ChildItem $s -ErrorAction SilentlyContinue | ForEach-Object {"
        "$subj=$_.Subject;$iss=$_.Issuer;$thumb=$_.Thumbprint;"
        "$nb=$_.NotBefore.ToString('o');$na=$_.NotAfter.ToString('o');"
        "Write-Output \"$subj|$iss|$thumb|$na|$s|$nb\""
        "}}"
    )
    try:
        proc = run_fn(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            shell=False,
            timeout=30.0,
        )
        out = (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return []

    cutoff = datetime.now(UTC)
    observations: list[RootCaObservation] = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        subject, issuer, thumb, not_after, store = parts[0], parts[1], parts[2], parts[3], parts[4]
        not_before = parts[5] if len(parts) > 5 else ""
        suspicious = bool(_SUSPICIOUS_ISSUER.search(subject) or _SUSPICIOUS_ISSUER.search(issuer))
        reason = ""
        if suspicious:
            reason = "Issuer or subject matches suspicious proxy/MITM keyword heuristics."
        try:
            nb_dt = datetime.fromisoformat(not_before.replace("Z", "+00:00")) if not_before else None
            if nb_dt and (cutoff - nb_dt).days <= recently_added_days:
                suspicious = True
                reason = reason or f"Root CA added within last {recently_added_days} days."
        except ValueError:
            pass
        observations.append(
            RootCaObservation(
                subject=subject,
                issuer=issuer,
                thumbprint=thumb,
                not_before=not_before,
                not_after=not_after,
                store=store,
                suspicious=suspicious,
                suspicion_reason=reason,
            )
        )
    return observations
