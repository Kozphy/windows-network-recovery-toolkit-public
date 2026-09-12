"""Pure policy evaluation helpers for Network State drift overlays.

:class:`NetworkStatePolicy` materializes lowercase tuple rules from optional JSON beside the
checkout. Evaluation never touches subprocesses — consumers embed results inside CLI payloads,
reports, and JSONL tails.

Decision intent:
    Enrich heuristic drift codes with coarse **blocked / observe / rollback_suggested** cues while
    keeping human operators in charge of restores.

Malformed policy files:
    Unreadable paths or JSON yield :meth:`NetworkStatePolicy.default`; partial keys fall back field by field where coded.

Timezone:
    N/A — policy JSON contains no timestamps; evaluation is instantaneous.

Raises:
    None — ``evaluate_network_state_policy`` always returns structured dict output.

See Also:
    ``shared/network_state_policy.example.json`` for authoring guidance.

"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..proxy_guard.parser import ParsedProxy


def _host_guess(parsed: ParsedProxy) -> str | None:
    """Return lowercase host heuristic from parser fields (fallback to raw ProxyServer blob)."""
    h = parsed.localhost_host or (parsed.raw or "").strip()
    return h.lower() if h else None


@dataclass(frozen=True)
class NetworkStatePolicy:
    """Declarative knobs loaded from optional ``network_state_policy.json``.

    Attributes:
        allowed_process_names: Substrings matched (case-insensitive) against attribution owner names.
        blocked_process_names: Substrings signalling ``blocked`` verdict when heuristic owners hit.
        allowed_proxy_hosts: Host tokens reducing loopback escalation severity when matched literally.
        blocked_proxy_hosts: Substrings denying configuration outright when seen in normalized host/raw.
        rollback_on_unknown_loopback: Elevate decision toward ``rollback_suggested`` advisory path.
        alert_on_unknown_loopback: Attach ``reasons`` entry when suspicion list references loopbacks.
    """

    allowed_process_names: tuple[str, ...]
    blocked_process_names: tuple[str, ...]
    allowed_proxy_hosts: tuple[str, ...]
    blocked_proxy_hosts: tuple[str, ...]
    rollback_on_unknown_loopback: bool
    alert_on_unknown_loopback: bool

    @classmethod
    def default(cls) -> NetworkStatePolicy:
        """Return conservative permissive baseline with alert-on-loopback only."""
        return cls((), (), (), (), False, True)

    @classmethod
    def from_file(cls, path: Path) -> NetworkStatePolicy:
        """Parse JSON dictionary into lowercase tuple fields tolerant of missing arrays.

        Args:
            path: Expected ``config/network_state_policy.json``.

        Returns:
            Materialized dataclass OR :meth:`default` upon any parse failure.

        Side effects:
            Read-only filesystem access without logging.

        Failure modes:
            Invalid UTF-8, JSON SyntaxError, or non-dict payloads transparently degrade to defaults.
        """
        if not path.is_file():
            return cls.default()
        try:
            blob = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls.default()
        if not isinstance(blob, dict):
            return cls.default()

        def tup(key: str) -> tuple[str, ...]:
            v = blob.get(key)
            if isinstance(v, list):
                return tuple(str(x).lower() for x in v)
            return ()

        return cls(
            allowed_process_names=tup("allowed_process_names"),
            blocked_process_names=tup("blocked_process_names"),
            allowed_proxy_hosts=tuple(str(x).lower() for x in blob.get("allowed_proxy_hosts", []) if isinstance(x, str)),
            blocked_proxy_hosts=tuple(str(x).lower() for x in blob.get("blocked_proxy_hosts", []) if isinstance(x, str)),
            rollback_on_unknown_loopback=bool(blob.get("rollback_on_unknown_loopback", False)),
            alert_on_unknown_loopback=bool(blob.get("alert_on_unknown_loopback", True)),
        )


def evaluate_network_state_policy(
    policy: NetworkStatePolicy,
    *,
    parsed: ParsedProxy,
    suspicions: list[str],
    attribution: dict[str, Any] | None,
) -> dict[str, Any]:
    """Rank heuristic drift overlays using allow/block tuples and loopback escalation flags.

    Args:
        policy: Effective policy snapshot.
        parsed: Parser output for ``current.proxy_server`` contextual host classification.
        suspicions: Deterministic textual codes emitted by drift heuristics.
        attribution:
            Loose owner mapping (typically ``proxy-attribution`` JSON subset with ``owners`` list).

    Returns:
        Mapping ``{"decision": str, "reasons": list[str]}`` where ``reasons`` is sorted deduplicated tokens.

    Side effects:
        None.

    Constraints:
        Process name checks use substring containment — maintain narrow literals in JSON to minimize false negatives.

    Engineering Notes:
        ``blocked`` dominates other states; rollback suggestions downgrade to advisory text only because execution still
        requires explicit typed confirms in CLI pathways.
    """
    reasons: list[str] = []
    decision = "observe"
    host_s = (_host_guess(parsed) or "") or ""

    for blocked in policy.blocked_proxy_hosts:
        if blocked and blocked in host_s:
            reasons.append(f"blocked_proxy_host:{blocked}")
            decision = "blocked"

    if decision != "blocked" and policy.blocked_proxy_hosts and parsed.raw:
        raw_l = parsed.raw.lower()
        for blocked in policy.blocked_proxy_hosts:
            if blocked in raw_l:
                reasons.append(f"blocked_literal:{blocked}")
                decision = "blocked"

    lowered_allowed_host = False
    for allowed in policy.allowed_proxy_hosts:
        if allowed and allowed in host_s:
            lowered_allowed_host = True
            break
        if allowed and parsed.raw and allowed in parsed.raw.lower():
            lowered_allowed_host = True
            break

    actor_names = []
    if attribution:
        owners = attribution.get("owners") or []
        if isinstance(owners, list):
            for o in owners:
                if isinstance(o, dict) and o.get("process_name"):
                    actor_names.append(str(o["process_name"]).lower())

    for blocked_name in policy.blocked_process_names:
        if blocked_name and any(blocked_name in n for n in actor_names):
            reasons.append(f"blocked_process_heuristic:{blocked_name}")
            if decision != "blocked":
                decision = "blocked"

    for allowed_name in policy.allowed_process_names:
        if allowed_name and any(allowed_name in n for n in actor_names):
            reasons.append(f"allowed_process_heuristic:{allowed_name}")
            if decision == "observe":
                decision = "allowed_context"

    loopback_unknown = any("loopback" in s for s in suspicions) or (
        parsed.is_localhost_proxy and not lowered_allowed_host
    )
    if loopback_unknown and policy.alert_on_unknown_loopback:
        reasons.append("alert_unknown_loopback_context")
    if loopback_unknown and policy.rollback_on_unknown_loopback and decision not in ("blocked",):
        reasons.append("rollback_suggested_unknown_loopback")
        decision = "rollback_suggested"

    return {"decision": decision, "reasons": sorted(set(reasons))}
