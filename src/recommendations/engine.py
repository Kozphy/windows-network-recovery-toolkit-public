"""Map the primary scored root cause to tiered, script-backed recommendations.

Tiers classify **risk and operator workflow** (`diagnose` read-only probes,
`safe` low-impact scripts, `guided` batch confirmations, `advanced` destructive
informational references). Nothing here executes subprocesses—callers enforce
confirmation and eligibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..decision_engine.scoring import CauseScore, RootCauseKey
from ..diagnostics.features import FeatureVector

RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]
RepairTier = Literal["diagnose", "safe", "guided", "advanced"]


@dataclass(frozen=True)
class Recommendation:
    """One human-readable step optionally pointing at ``scripts\\`` relative paths.

    Attributes:
        title: Short label for consoles and plaintext export.
        detail: Longer operator guidance text.
        script_relative: Repo-relative ``.bat/.ps1`` path or ``None`` for manuals.
        tier: Lifecycle bucket controlling how callers should gate execution.
        risk: Relative damage potential (LOW/MEDIUM/HIGH).
        reversible_notes: How to unwind or reassess impact after the step.
    """

    title: str
    detail: str
    script_relative: str | None
    tier: RepairTier
    risk: RiskLevel
    reversible_notes: str


@dataclass(frozen=True)
class RecommendationBundle:
    """Immutable quadrants surfaced by CLI ``recommend`` and JSON export."""

    diagnose: tuple[Recommendation, ...]
    safe: tuple[Recommendation, ...]
    guided: tuple[Recommendation, ...]
    advanced: tuple[Recommendation, ...]

    def flatten_for_audit(self) -> list[dict[str, str | None]]:
        """Produce flat rows embedding tier label for JSONL summaries."""
        rows: list[dict[str, str | None]] = []
        for bucket, label in (
            (self.diagnose, "diagnose"),
            (self.safe, "repair-safe"),
            (self.guided, "guided"),
            (self.advanced, "advanced"),
        ):
            for item in bucket:
                rows.append(
                    {
                        "mode": label,
                        "title": item.title,
                        "risk": item.risk,
                        "script": item.script_relative,
                    }
                )
        return rows


def _r(
    title: str,
    detail: str,
    *,
    script: str | None,
    tier: RepairTier,
    risk: RiskLevel,
    reversible: str,
) -> Recommendation:
    return Recommendation(
        title=title,
        detail=detail,
        script_relative=script,
        tier=tier,
        risk=risk,
        reversible_notes=reversible,
    )


def build_recommendations(
    primary_cause: CauseScore,
    features: FeatureVector,
    repo_root: Path,
) -> RecommendationBundle:
    """Map root-cause hypothesis to tiered actions.

    Args:
        primary_cause: Primary ``CauseScore`` from `score_root_causes` (used for
            branch selection only; confidences are not re-ranked here).
        features: Feature vector (used for exhaustion-driven guided items).
        repo_root: Reserved for future path validation; currently unused.

    Returns:
        ``RecommendationBundle`` honoring the tier contract:
        - diagnose: read-only collection
        - safe: low risk, generally reversible via OS UI or small cache/proxy clears
        - guided: user must confirm in batch wrapper; may reset stack components
        - advanced: destructive or policy sensitive (firewall) — never chained automatically

    Raises:
        None.
    """
    _ = repo_root
    cause: RootCauseKey = primary_cause.cause

    diag = (
        _r(
            "Re-run structured diagnosis",
            "Capture another snapshot after any network change.",
            script=r"scripts\auto_diagnose.bat",
            tier="diagnose",
            risk="LOW",
            reversible="Read-only.",
        ),
        _r(
            "Optional time-series monitoring",
            "If failures are intermittent, collect state transitions.",
            script=r"scripts\monitor_network.ps1",
            tier="diagnose",
            risk="LOW",
            reversible="Read-only logging.",
        ),
    )

    universal_safe = (
        _r(
            "Document current symptoms",
            "Note whether only a single browser fails while other apps work.",
            script=None,
            tier="safe",
            risk="LOW",
            reversible="N/A",
        ),
    )

    if cause == "dns_issue":
        return RecommendationBundle(
            diagnose=diag,
            safe=(
                *universal_safe,
                _r(
                    "Flush resolver cache",
                    "Clears stale negative cache entries; does not delete system config files.",
                    script=r"scripts\reset_dns.bat",
                    tier="safe",
                    risk="LOW",
                    reversible="DNS settings unchanged; cache repopulates naturally.",
                ),
            ),
            guided=(),
            advanced=(),
        )

    if cause == "proxy_issue":
        return RecommendationBundle(
            diagnose=diag,
            safe=(
                *universal_safe,
                _r(
                    "Clear WinHTTP and user proxy knobs",
                    "Removes stale manual proxy entries — review enterprise policy if managed.",
                    script=r"scripts\reset_proxy.bat",
                    tier="safe",
                    risk="LOW",
                    reversible="Reconfigure proxy if required after testing.",
                ),
            ),
            guided=(),
            advanced=(),
        )

    if cause == "firewall_issue":
        return RecommendationBundle(
            diagnose=diag,
            safe=(
                *universal_safe,
                _r(
                    "Manual firewall review",
                    "Inspect Windows Defender Firewall with Advanced Security; no automatic reset from this toolkit.",
                    script=None,
                    tier="safe",
                    risk="LOW",
                    reversible="N/A",
                ),
            ),
            guided=(
                _r(
                    "Layered connectivity evidence",
                    "Confirm whether TCP/HTTPS symptoms align with a third-party security product.",
                    script=r"scripts\check_network.bat",
                    tier="guided",
                    risk="LOW",
                    reversible="Read-only.",
                ),
            ),
            advanced=(
                _r(
                    "Firewall reset script (explicit confirmation only)",
                    "Use only when firewall rules are suspected broken; restores defaults — review rules after.",
                    script=r"scripts\reset_firewall.bat",
                    tier="advanced",
                    risk="HIGH",
                    reversible="Manual effort to restore custom rules.",
                ),
            ),
        )

    if cause == "network_adapter_issue":
        return RecommendationBundle(
            diagnose=diag,
            safe=(
                *universal_safe,
                _r(
                    "Adapter triage",
                    "Toggle airplane mode, reconnect Wi‑Fi, or re-seat Ethernet; avoid disabling adapters silently.",
                    script=None,
                    tier="safe",
                    risk="LOW",
                    reversible="User-driven.",
                ),
            ),
            guided=(
                _r(
                    "Guided stack repair (after backup / confirmation)",
                    "Only after link health is confirmed stable — disruptive to active connections.",
                    script=r"scripts\one_click_fix.bat",
                    tier="guided",
                    risk="MEDIUM",
                    reversible="May require reboot; settings generally restorable via UI.",
                ),
            ),
            advanced=(),
        )

    if cause == "isp_router_issue":
        bundle = RecommendationBundle(
            diagnose=diag,
            safe=(
                *universal_safe,
                _r(
                    "Restart CPE / test alternate network",
                    "Power-cycle modem/router and retry; mobile hotspot isolates ISP issues.",
                    script=None,
                    tier="safe",
                    risk="LOW",
                    reversible="N/A",
                ),
            ),
            guided=(),
            advanced=(),
        )
        if (
            features.time_wait_count >= 5000
            or features.established_count >= 8000
        ):
            guided = (
                _r(
                    "Check for connection exhaustion",
                    "Read-only exhaustion scan for apps leaking sockets.",
                    script=r"scripts\check_connection_exhaustion.bat",
                    tier="guided",
                    risk="LOW",
                    reversible="Read-only.",
                ),
            )
            return RecommendationBundle(
                diagnose=bundle.diagnose,
                safe=bundle.safe,
                guided=guided,
                advanced=bundle.advanced,
            )
        return bundle

    if cause == "winsock_issue":
        return RecommendationBundle(
            diagnose=diag,
            safe=(
                *universal_safe,
                _r(
                    "Narrow the failure",
                    "Collect read-only evidence before stack repair.",
                    script=r"scripts\check_network.bat",
                    tier="safe",
                    risk="LOW",
                    reversible="Read-only.",
                ),
            ),
            guided=(
                _r(
                    "Winsock/TCP/IP guided reset",
                    "Runs netsh repairs for Winsock + TCP/IP stack, flushes DNS cache, clears proxies — requires reboot advisory.",
                    script=r"scripts\one_click_fix.bat",
                    tier="guided",
                    risk="MEDIUM",
                    reversible="Mostly reversible via configuration, but disruptive.",
                ),
            ),
            advanced=(),
        )

    if cause == "browser_only_issue":
        return RecommendationBundle(
            diagnose=diag,
            safe=(
                *universal_safe,
                _r(
                    "Browser isolation",
                    "Test InPrivate/Incognito, another browser profile, or alternate engine.",
                    script=None,
                    tier="safe",
                    risk="LOW",
                    reversible="N/A",
                ),
            ),
            guided=(
                _r(
                    "Connection hygiene if symptoms appear after uptime",
                    "Check for socket leaks if failures emerge over time while automated probes still pass.",
                    script=r"scripts\check_connection_exhaustion.bat",
                    tier="guided",
                    risk="LOW",
                    reversible="Read-only.",
                ),
            ),
            advanced=(),
        )

    # Fallback (should be rare because cause set is closed)
    return RecommendationBundle(
        diagnose=diag,
        safe=universal_safe,
        guided=(
            _r(
                "Guided auto-fix after human review",
                "Escalate cautiously when evidence is mixed.",
                script=r"scripts\auto_fix.bat",
                tier="guided",
                risk="MEDIUM",
                reversible="Depends on executed steps.",
            ),
        ),
        advanced=(),
    )
