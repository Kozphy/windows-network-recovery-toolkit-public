"""Structured safe/guided/advanced pointers for ``diagnose-live`` consumers.

Decision intent:
    Encode operator next steps referencing in-repo scripts/CLIs—never silently execute shells.

Outputs:
    JSON-serializable dicts keyed by tier with fixed field names CLI rendering expects.

Side effects:
    None (pure transformation).
"""

from __future__ import annotations

from typing import Any

from .live_scoring import LiveHypothesisScore


def live_recommendation_bundle(top: LiveHypothesisScore, *, primary_hypothesis: str) -> dict[str, list[dict[str, Any]]]:
    """Map hypotheses into ``diagnose``/``repair_safe``/``guided``/``advanced`` item lists.

    Args:
        top: Ranked hypothesis used for explanatory tie-ins.
        primary_hypothesis: Canonical key string influencing repair tier selection.

    Returns:
        Dict with tier keys each listing metadata dicts (title, optional script path, rationale).

    Constraints:
        Script paths preserve Windows separators as stored literals; callers must normalize if needed.

    Audit Notes:
        Items reference ``logs/repair_audit.jsonl``/`proxy_guard_events.jsonl`; verify those artefacts on disk post-run.
    """
    diagnose: list[dict[str, Any]] = [
        _item(
            "Capture another live snapshot after any change.",
            None,
            "diagnose",
            "LOW",
            "snapshot",
            "Read-only JSON under reports/snapshots/.",
        ),
        _item(
            "Observe proxy churn over time.",
            r"scripts\proxy_monitor.bat",
            "diagnose",
            "LOW",
            None,
            "Append-only logs/proxy_guard_events.jsonl when using CLI.",
        ),
    ]

    repair_safe: list[dict[str, Any]] = []
    guided: list[dict[str, Any]] = []
    advanced: list[dict[str, Any]] = []

    if primary_hypothesis in {
        "unexpected_user_proxy",
        "local_proxy_hijack",
        "browser_proxy_path_issue",
        "localhost_proxy_owner_suspicious",
    }:
        repair_safe.append(
            _item(
                "Preview disabling WinINET HKCU user proxy flags (confirmation required).",
                r"scripts\proxy_disable.bat",
                "safe",
                "LOW",
                "proxy_disable",
                "Does not touch WinHTTP; may be re-applied by policy software.",
            ),
        )
        repair_safe.append(
            _item(
                "Clear WinHTTP + user proxy via guided script (batch confirmation).",
                r"scripts\reset_proxy.bat",
                "safe",
                "LOW",
                None,
                "Escalation when both WinHTTP and user settings are suspect.",
            ),
        )
        guided.append(
            _item(
                "Run connection exhaustion diagnostics if sockets climb over time.",
                r"scripts\check_connection_exhaustion.bat",
                "guided",
                "LOW",
                None,
                "Read-only unless paired with remediation.",
            ),
        )

    if primary_hypothesis == "dns_resolution_issue":
        repair_safe.append(
            _item(
                "Flush DNS resolver cache.",
                r"scripts\reset_dns.bat",
                "safe",
                "LOW",
                None,
                "Does not mutate static DNS assignments.",
            ),
        )

    if primary_hypothesis == "socket_exhaustion":
        guided.append(
            _item(
                "Investigate leaky applications/services holding sockets.",
                r"scripts\check_connection_exhaustion.bat",
                "guided",
                "LOW",
                None,
                "Prefer closing offending apps before stack resets.",
            ),
        )

    if primary_hypothesis == "winsock_corruption_possible":
        guided.append(
            _item(
                "Guided Winsock/TCP/IP reset (disruptive, confirm in batch wrapper).",
                r"scripts\one_click_fix.bat",
                "guided",
                "MEDIUM",
                None,
                "Requires reboot advisory inside script.",
            ),
        )

    return {
        "diagnose": diagnose,
        "repair_safe": repair_safe,
        "guided_repair": guided,
        "advanced_repair": advanced,
    }


def _item(
    title: str,
    script: str | None,
    tier: str,
    risk: str,
    action_key: str | None,
    detail: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "detail": detail,
        "script": script,
        "tier": tier,
        "risk": risk,
        "reversible_notes": "Review settings after change; rerun snapshot.",
        "action_key": action_key,
    }
