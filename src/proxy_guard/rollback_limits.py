"""Rollback rate limiting and cooldown — prevents infinite rollback loops."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .config import RollbackLimitSettings


@dataclass
class RollbackLimiter:
    """Tracks rollback attempts using monotonic clocks (immune to NTP jumps).

    Rules:
        - After a rollback, ``cooldown`` blocks further auto-rollbacks until elapsed.
        - Within a rolling ``window``, at most ``max_per_window`` rollbacks apply.

    Pure transition: call :meth:`evaluate` then :meth:`record` only when rollback runs.
    """

    settings: RollbackLimitSettings
    _clock: Callable[[], float] = field(default=time.monotonic)
    _rollback_times: list[float] = field(default_factory=list)
    _cooldown_until_mono: float | None = None

    def evaluate(self) -> tuple[bool, str]:
        """Return whether an automatic rollback may proceed and a stable reason code."""
        now = float(self._clock())
        if self._cooldown_until_mono is not None and now < self._cooldown_until_mono:
            remain = self._cooldown_until_mono - now
            return False, f"rollback_cooldown_active:{remain:.1f}s"

        window = max(1.0, self.settings.window_seconds)
        horizon = now - window
        self._rollback_times = [t for t in self._rollback_times if t >= horizon]

        if len(self._rollback_times) >= self.settings.max_rollbacks_per_window:
            return False, "rollback_rate_limited_in_window"

        return True, "ok"

    def record_rollback(self) -> None:
        """Record that a rollback was executed (call once per actual attempt)."""
        now = float(self._clock())
        self._rollback_times.append(now)
        cool = max(0.0, self.settings.cooldown_seconds)
        self._cooldown_until_mono = now + cool
