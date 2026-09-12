"""Human-readable condensation of remediation argv plans (CLI stdout helper)."""

from __future__ import annotations

from ..proxy_guard.remediation import ProxyDisableMutation


def summarize_mutations_plaintext(mut: tuple[ProxyDisableMutation, ...]) -> str:
    """Join each mutation ``human`` line with newlines for console review."""
    return "\n".join(m.human for m in mut)
