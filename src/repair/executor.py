"""Sequential ``reg.exe`` mutation runner with explicit ``dry_run`` semantics."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from ..proxy_guard.remediation import ProxyDisableMutation


@dataclass(frozen=True)
class RegApplyResult:
    """Capture argv echo plus streams for auditing each registry mutation attempt."""

    argv: tuple[str, ...]
    returncode: int
    stderr: str
    stdout: str


def apply_mutations(
    mutations: tuple[ProxyDisableMutation, ...],
    *,
    dry_run: bool,
) -> tuple[RegApplyResult, ...]:
    """Run each ``ProxyDisableMutation`` argv with ``shell=False``.

    Args:
        mutations: Ordered WinINET disables (caller constructs via remediation helpers).
        dry_run: When true, emits synthetic stdout without touching ``reg.exe``.

    Returns:
        Parallel tuple of outcomes (including timeouts mapped to synthetic rows).

    Side effects:
        Non-dry mutations invoke ``subprocess.run`` against local ``reg.exe``.

    Idempotency:
        Applying identical mutations twice yields duplicate HKCU writes—operators should rely
        on preview + audits before repeats.

    Audit Notes:
        Persist returned argv/exit codes beside JSONL timelines for incident review.
    """
    outcomes: list[RegApplyResult] = []
    for m in mutations:
        if dry_run:
            outcomes.append(RegApplyResult(m.argv, 0, "", "[dry-run] not executed"))
            continue
        try:
            proc = subprocess.run(
                list(m.argv),
                capture_output=True,
                text=True,
                shell=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            outcomes.append(RegApplyResult(m.argv, -1, str(exc), ""))
            continue
        outcomes.append(
            RegApplyResult(
                m.argv,
                proc.returncode,
                proc.stderr or "",
                proc.stdout or "",
            ),
        )
    return tuple(outcomes)


def apply_reg_argv_sequences(
    argv_list: tuple[tuple[str, ...], ...],
    *,
    dry_run: bool,
    subprocess_timeout_seconds: float = 30,
) -> tuple[RegApplyResult, ...]:
    """Run arbitrary ``reg.exe`` argument vectors without shell redirection.

    Used for richer WinINET restore paths than :class:`ProxyDisableMutation` previews.

    Args:
        argv_list: Ordered ``argv`` tuples (each must begin with executable name).
        dry_run: When true, skips subprocess calls and echoes synthetic successes.
        subprocess_timeout_seconds: Per-invocation watchdog.

    Returns:
        One :class:`RegApplyResult` per attempted argv.

    Side effects:
        Non-dry invocations mutate HKCU proxy keys targeted by callers.
    """
    outcomes: list[RegApplyResult] = []
    for argv in argv_list:
        if dry_run:
            outcomes.append(RegApplyResult(tuple(argv), 0, "", "[dry-run] not executed"))
            continue
        try:
            proc = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                shell=False,
                timeout=subprocess_timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            outcomes.append(RegApplyResult(tuple(argv), -1, str(exc), ""))
            continue
        outcomes.append(
            RegApplyResult(
                tuple(argv),
                proc.returncode,
                proc.stderr or "",
                proc.stdout or "",
            ),
        )
    return tuple(outcomes)
