"""Post-mutation WinINET verification (read-only registry)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.models import ProxyRegistrySnapshot


@dataclass(frozen=True)
class ProxyDisableVerification:
    """Structured outcome after attempted HKCU proxy disable."""

    ok: bool
    proxy_enable_observed: int | None
    detail: str
    expected_proxy_enable: int = 0

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
            "ok": self.ok,
            "proxy_enable_observed": self.proxy_enable_observed,
            "expected_proxy_enable": self.expected_proxy_enable,
            "detail": self.detail,
        }


def verify_proxy_disabled(
    snapshot: ProxyRegistrySnapshot,
    *,
    expected: int = 0,
) -> ProxyDisableVerification:
    """Return whether ``ProxyEnable`` matches the safe disabled expectation.

    Args:
        snapshot: Fresh registry read after mutations.
        expected: Typically ``0`` for disabled.

    Returns:
        :class:`ProxyDisableVerification` suitable for JSON audits.
    """
    obs = snapshot.proxy_enable
    if obs is None:
        return ProxyDisableVerification(
            ok=False,
            proxy_enable_observed=None,
            detail="ProxyEnable could not be read after mutation (reg query failed).",
            expected_proxy_enable=expected,
        )
    if obs != expected:
        return ProxyDisableVerification(
            ok=False,
            proxy_enable_observed=obs,
            detail=f"ProxyEnable remained {obs}; expected {expected}.",
            expected_proxy_enable=expected,
        )
    return ProxyDisableVerification(
        ok=True,
        proxy_enable_observed=obs,
        detail="ProxyEnable matches expected disabled value.",
        expected_proxy_enable=expected,
    )
