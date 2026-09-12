"""Polling-style heuristics (process name keywords — **not registry write attribution**)."""

from __future__ import annotations

from typing import Any

from platform_core.attribution.base import AttributionProvider
from platform_core.events import ActorAttribution

_HIGH_HINTS = frozenset(
    {"clash", "v2ray", "shadowsocks", "fiddler", "charles", "wireguard"},
)


class PollingHeuristicProvider:
    """Lightweight deterministic keyword skim over optional ``process_names_sample``."""

    name = "polling_heuristic_v1"

    def describe(self) -> str:
        """Provide describe behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return (
            "Skims optional sanitized process tokens for risky proxy tooling names; confidence "
            "remains heuristic only."
        )

    def attribute(self, context: dict[str, Any]) -> ActorAttribution:
        """Provide attribute behavior for toolkit workflows.

        Args:
            context: Value supplied by the caller for context.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        tokens = []
        raw = context.get("process_names_sample")
        if isinstance(raw, list):
            tokens.extend(str(x).lower() for x in raw)
        elif isinstance(raw, str):
            tokens.append(raw.lower())
        hits = [tok for tok in tokens if tok and any(k in tok for k in _HIGH_HINTS)]
        if hits:
            return ActorAttribution(
                confidence="low",
                method="process_keyword_snapshot",
                notes=[
                    "Heuristic correlation only.",
                    "No proof tying processes to HKCU/System configuration writers.",
                ],
                provider=self.name,
                details={"matching_tokens": hits[:10]},
            )
        return ActorAttribution(
            confidence="none",
            method="polling_no_match",
            notes=["Keyword snapshot yielded no flagged names."],
            provider=self.name,
            details={"tokens_checked": len(tokens)},
        )


def default_polling_provider() -> AttributionProvider:
    """Default polling provider for toolkit workflows.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return PollingHeuristicProvider()
