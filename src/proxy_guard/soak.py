"""Post-remediation soak monitor for WinINET ``ProxyEnable`` stickiness.

Module responsibility:
    After confirmed ``proxy-disable``, poll HKCU ``ProxyEnable`` for a configured
    window and classify **STABLE** vs **REMEDIATION_NOT_STICKY**.

System placement:
    Invoked from :mod:`remediation` / ``python -m src proxy-disable --soak-minutes``.

Key invariants:
    * Soak performs **read-only** registry polls — never auto-resets proxy in a loop.
    * ``soak_minutes <= 0`` skips monitoring and returns ``STABLE`` with
      ``detail=soak_skipped``.

Input assumptions:
    Caller already applied disable mutations; ``read_proxy_registry`` reflects HKCU.

Output guarantees:
    :class:`SoakResult` with ``status`` in ``{STABLE, REMEDIATION_NOT_STICKY}``,
    sample count, and last observed enable flag.

Idempotency:
    Repeated soak runs are independent; each run only reads registry state.

Failure modes:
    If an active reverter sets ``ProxyEnable=1`` during the window, status is
    ``REMEDIATION_NOT_STICKY`` — operators must stop the reverter before retrying.

Audit Notes:
    Soak outcomes append to ``logs/repair_audit.jsonl`` (subtype
    ``proxy_disable_soak``). Pair with :mod:`flip_flop` when toggles exceed policy
    thresholds.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .registry import read_proxy_registry


@dataclass(frozen=True)
class SoakResult:
    """Outcome of monitoring HKCU proxy keys after remediation."""

    status: str  # STABLE | REMEDIATION_NOT_STICKY
    soak_minutes: float
    poll_seconds: float
    samples: int
    detail: str
    last_proxy_enable: int | None

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
            "status": self.status,
            "soak_minutes": self.soak_minutes,
            "poll_seconds": self.poll_seconds,
            "samples": self.samples,
            "detail": self.detail,
            "last_proxy_enable": self.last_proxy_enable,
        }


def run_remediation_soak(
    *,
    soak_minutes: float,
    poll_seconds: float = 5.0,
    run: Callable[..., Any],
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> SoakResult:
    """Poll WinINET ``ProxyEnable`` until deadline or re-enable detected.

    Args:
        soak_minutes: Window length in minutes; ``<= 0`` skips polling and returns
            ``STABLE`` with ``detail=soak_skipped``.
        poll_seconds: Sleep interval between registry reads (default 5).
        run: Subprocess runner forwarded to :func:`registry.read_proxy_registry`.
        sleep_fn: Injectable sleep for tests.
        monotonic_fn: Injectable monotonic clock for tests.

    Returns:
        :class:`SoakResult` with ``status`` ``STABLE`` or ``REMEDIATION_NOT_STICKY``.

    Side effects:
        Read-only HKCU registry queries only.

    Audit Notes:
        ``REMEDIATION_NOT_STICKY`` indicates an active reverter — stop the suspected
        process tree before repeating ``proxy-disable`` (see ``docs/proxy_green_definition.md``).
    """

    if soak_minutes <= 0:
        return SoakResult(
            status="STABLE",
            soak_minutes=0.0,
            poll_seconds=poll_seconds,
            samples=0,
            detail="soak_skipped",
            last_proxy_enable=None,
        )

    deadline = monotonic_fn() + soak_minutes * 60.0
    samples = 0
    last_en: int | None = None
    while monotonic_fn() < deadline:
        reg = read_proxy_registry(run=run)
        samples += 1
        en = reg.proxy_enable
        last_en = en
        if en == 1:
            return SoakResult(
                status="REMEDIATION_NOT_STICKY",
                soak_minutes=soak_minutes,
                poll_seconds=poll_seconds,
                samples=samples,
                detail=(
                    "ProxyEnable returned to 1 during soak. Suspected active reverter. "
                    "Do not keep resetting in a loop — identify writer (WMI / Procmon / Sysmon EID 13)."
                ),
                last_proxy_enable=en,
            )
        sleep_fn(poll_seconds)

    return SoakResult(
        status="STABLE",
        soak_minutes=soak_minutes,
        poll_seconds=poll_seconds,
        samples=samples,
        detail="no_proxy_reenable_during_soak",
        last_proxy_enable=last_en,
    )
