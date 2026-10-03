"""Post-change connectivity validation for Proxy Guard decisions.

Module responsibility:
    Execute deterministic post-change network checks (DNS, TCP 443, HTTPS HEAD) and compare
    pre/post snapshots to detect browser-path regressions after WinINET proxy changes.

System placement:
    Called from :mod:`src.proxy_guard.guard` only after registry drift is detected and before
    final decision payloads are emitted.

Key invariants:
    - Every probe runs with ``shell=False`` and bounded timeout.
    - Probe failures are represented as structured rows, not raised by default.
    - Snapshot output remains JSON-serializable for append-only audit sinks.

Audit Notes:
    These checks reduce false "allowed" outcomes when localhost proxies exist but browser-path
    connectivity regresses. Inspect stdout/stderr fields in pipeline JSONL for incident replay.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import ProxySnapshot


@dataclass(frozen=True)
class CommandProbeResult:
    """Single command probe outcome for connectivity validation.

    Attributes:
        name: Stable probe key emitted to audit sinks.
        ok: True when return code indicates success for this probe.
        returncode: Subprocess return code, ``-1`` for timeout/OS-level failures.
        stdout: Captured command standard output.
        stderr: Captured command standard error.
        permission_limited: True when probe failed due to permissions.
    """

    name: str
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    permission_limited: bool = False

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "name": self.name,
            "ok": self.ok,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "permission_limited": self.permission_limited,
        }


@dataclass(frozen=True)
class ConnectivitySnapshot:
    """Connectivity check bundle captured at one point in time.

    Includes command probe outputs plus WinINET fields used to correlate regressions
    with proxy toggle transitions.
    """

    tcp_443_google: CommandProbeResult
    https_google: CommandProbeResult
    https_microsoft: CommandProbeResult
    dns_google: CommandProbeResult
    wininet_proxy_enable: int | None
    wininet_proxy_server: str | None

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "tcp_443_google": self.tcp_443_google.to_jsonable(),
            "https_google": self.https_google.to_jsonable(),
            "https_microsoft": self.https_microsoft.to_jsonable(),
            "dns_google": self.dns_google.to_jsonable(),
            "wininet_proxy_enable": self.wininet_proxy_enable,
            "wininet_proxy_server": self.wininet_proxy_server,
        }


@dataclass(frozen=True)
class ConnectivityValidation:
    """Pre/post connectivity comparison result consumed by decision synthesis."""

    pre_change: ConnectivitySnapshot | None
    post_change: ConnectivitySnapshot
    regression_detected: bool
    regression_type: str
    summary: str

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "pre_change": None if self.pre_change is None else self.pre_change.to_jsonable(),
            "post_change": self.post_change.to_jsonable(),
            "regression_detected": self.regression_detected,
            "regression_type": self.regression_type,
            "summary": self.summary,
        }


def _probe(
    name: str,
    argv: list[str],
    *,
    run: Callable[..., Any] = subprocess.run,
    timeout_seconds: float = 15.0,
) -> CommandProbeResult:
    """Execute one external probe command with safe defaults.

    Args:
        name: Stable logical probe name.
        argv: Argument vector for subprocess execution.
        run: Injectable subprocess runner used by tests and production.
        timeout_seconds: Per-probe timeout budget.

    Returns:
        CommandProbeResult: Structured row with return code and output streams.

    Side effects:
        Executes one external command on the local machine.

    Failure modes:
        Timeouts and OS errors return ``ok=False`` rows; errors are not raised to keep
        guard loops resilient.
    """
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return CommandProbeResult(name=name, ok=False, returncode=-1, stdout="", stderr=str(exc))
    except OSError as exc:
        msg = str(exc)
        limited = "access is denied" in msg.lower() or "permission" in msg.lower()
        return CommandProbeResult(
            name=name,
            ok=False,
            returncode=-1,
            stdout="",
            stderr=msg,
            permission_limited=limited,
        )
    out = proc.stdout or ""
    err = proc.stderr or ""
    ok = int(proc.returncode) == 0
    return CommandProbeResult(
        name=name, ok=ok, returncode=int(proc.returncode), stdout=out, stderr=err
    )


def capture_connectivity_snapshot(
    *,
    run: Callable[..., Any] = subprocess.run,
    snapshot: ProxySnapshot,
    timeout_seconds: float = 15.0,
) -> ConnectivitySnapshot:
    """Run deterministic connectivity probes and return a snapshot.

    Args:
        run: Injectable subprocess runner.
        snapshot: Current proxy snapshot providing WinINET context fields.
        timeout_seconds: Per-command timeout budget.

    Returns:
        ConnectivitySnapshot: Result of DNS/TCP443/HTTPS checks and WinINET values.

    Side effects:
        Executes ``powershell``, ``curl``, and ``nslookup`` commands.

    Idempotency:
        Re-running without environment changes yields equivalent logical outcomes but may
        vary in raw stdout formatting/timing text from external commands.
    """
    tcp = _probe(
        "post_change_tcp443_check",
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Test-NetConnection www.google.com -Port 443 | Select-Object -ExpandProperty TcpTestSucceeded",
        ],
        run=run,
        timeout_seconds=timeout_seconds,
    )
    https_google = _probe(
        "post_change_https_check_google",
        ["curl", "-I", "https://www.google.com"],
        run=run,
        timeout_seconds=timeout_seconds,
    )
    https_microsoft = _probe(
        "post_change_https_check_microsoft",
        ["curl", "-I", "https://www.microsoft.com"],
        run=run,
        timeout_seconds=timeout_seconds,
    )
    dns = _probe(
        "post_change_dns_check",
        ["nslookup", "www.google.com"],
        run=run,
        timeout_seconds=timeout_seconds,
    )
    return ConnectivitySnapshot(
        tcp_443_google=tcp,
        https_google=https_google,
        https_microsoft=https_microsoft,
        dns_google=dns,
        wininet_proxy_enable=snapshot.proxy_enable,
        wininet_proxy_server=snapshot.proxy_server,
    )


def compare_connectivity(
    *,
    pre_change: ConnectivitySnapshot | None,
    post_change: ConnectivitySnapshot,
) -> ConnectivityValidation:
    """Compare pre/post snapshots and classify regression type.

    Args:
        pre_change: Baseline snapshot from before registry change, when available.
        post_change: Snapshot captured after registry change.

    Returns:
        ConnectivityValidation: Regression flag, type, and summary for decision payloads.

    Constraints:
        Classification is deterministic and intentionally conservative; it does not claim root
        cause, only signals likely browser-path/HTTPS-path regression patterns.
    """
    if pre_change is None:
        return ConnectivityValidation(
            pre_change=None,
            post_change=post_change,
            regression_detected=False,
            regression_type="insufficient_pre_change_baseline",
            summary="No pre-change baseline was available; post-change checks only.",
        )

    regressions: list[str] = []
    if pre_change.https_google.ok and not post_change.https_google.ok:
        regressions.append("https_google_regressed")
    if pre_change.https_microsoft.ok and not post_change.https_microsoft.ok:
        regressions.append("https_microsoft_regressed")
    if pre_change.tcp_443_google.ok and not post_change.tcp_443_google.ok:
        regressions.append("tcp_443_regressed")
    if pre_change.dns_google.ok and not post_change.dns_google.ok:
        regressions.append("dns_regressed")

    if regressions:
        if (
            post_change.tcp_443_google.ok
            and not post_change.https_google.ok
            and post_change.dns_google.ok
        ):
            reg_type = "https_path_regression_tcp_ok_dns_ok"
        else:
            reg_type = "connectivity_regression"
        return ConnectivityValidation(
            pre_change=pre_change,
            post_change=post_change,
            regression_detected=True,
            regression_type=reg_type,
            summary="Connectivity regressed after proxy-related registry change.",
        )

    return ConnectivityValidation(
        pre_change=pre_change,
        post_change=post_change,
        regression_detected=False,
        regression_type="none",
        summary="No connectivity regression detected across pre/post change checks.",
    )
