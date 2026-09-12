"""Typed contracts for Proxy Guard snapshots, attribution, policy verdicts, rollback, and audit rows.

Used by ``guard``, ``audit``, Snapshots persisted as ``reports/proxy_guard_lkg.json`` use
:class:`ProxySnapshot` JSON shapes (see ``to_jsonable`` helpers).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

ConfidenceLevel = str  # values: verified | high | medium | low | unknown
AttributionMode = Literal["verified_eventlog", "best_effort_process_snapshot", "unknown"]
GuardDecisionKind = Literal["allowed", "blocked", "observe"]

HeuristicAttributionConfidence = Literal["high", "medium", "low", "unknown"]
HeuristicAttributionMethod = Literal[
    "psutil_snapshot_heuristic",
    "wmi_snapshot_heuristic",
    "unavailable",
    "sysmon_event_13",
    "procmon_csv",
    "localhost_listener",
    "process_inventory_heuristic",
    "registry_polling",
    "unknown",
]


def _json_leaf(v: Any) -> Any:
    """Recursively convert dataclass instances inside dict/list leaves for JSONL."""
    if hasattr(v, "to_jsonable"):
        return v.to_jsonable()
    if isinstance(v, dict):
        return {str(k): _json_leaf(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_json_leaf(x) for x in v]
    return v


@dataclass(frozen=True)
class ActorCandidate:
    """Heuristic-only process cue for pipeline ``attribute`` JSON (never an accusation).

    Distinct from :class:`ProcessIdentity` used by policy/EventLog attribution paths.
    """

    pid: int
    process_name: str
    process_path: str | None
    parent_pid: int | None
    command_line: str | None
    score: int
    reasons: tuple[str, ...]

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        row = {
            "pid": self.pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "parent_pid": self.parent_pid,
            "command_line": self.command_line,
            "score": self.score,
            "reasons": list(self.reasons),
        }
        if self.process_path:
            row["image_path"] = self.process_path
        return row


@dataclass(frozen=True)
class HeuristicPipelineAttribution:
    """Best-effort / layered attribution export for unified ``schema_version`` 1 pipeline rows.

    ``high`` confidence is reserved for correlated Sysmon/Procmon registry SetValue tiers produced by
    :mod:`~src.proxy_guard.attribution_engine`. Listener and psutil-derived rows remain capped per caller.
    """

    candidate_actor: ActorCandidate | None
    attribution_confidence: HeuristicAttributionConfidence
    attribution_method: HeuristicAttributionMethod | str
    attribution_notes: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...] = ()

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        row: dict[str, Any] = {
            "candidate_actor": None if self.candidate_actor is None else self.candidate_actor.to_jsonable(),
            "attribution_confidence": self.attribution_confidence,
            "attribution_method": self.attribution_method,
            "attribution_notes": list(self.attribution_notes),
        }
        if self.evidence:
            row["evidence"] = list(self.evidence)
        return row


@dataclass(frozen=True)
class ProcessIdentity:
    """Identifies a Windows process surfaced by event logs or heuristic snapshots."""

    pid: int | None
    ppid: int | None
    exe: str | None
    name: str | None
    cmdline: str | None
    create_time_utc: str | None
    user: str | None
    source: Literal[
        "eventlog_security_registry",
        "eventlog_sysmon_registry",
        "best_effort_listen_owner",
        "best_effort_psutil",
        "best_effort_recent_snapshot",
        "unknown",
    ]

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return asdict(self)


@dataclass(frozen=True)
class AttributionResult:
    """Evidence bundle for WHO likely changed HKCU proxy data.

    Never claim certainty unless ``mode`` is ``verified_eventlog`` with Security/Sysmon
    registry auditing (see docs).
    """

    mode: AttributionMode
    confidence: ConfidenceLevel
    process: ProcessIdentity | None
    evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

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
            "mode": self.mode,
            "confidence": self.confidence,
            "process": None if self.process is None else self.process.to_jsonable(),
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ProxySnapshot:
    """Point-in-time join of HKCU WinINET probe data, WinHTTP narrative, SCM configs, env."""

    proxy_enable: int | None
    proxy_server: str | None
    proxy_override: str | None
    auto_config_url: str | None
    auto_detect: int | None
    winhttp_proxy: str
    winhttp_direct_access: bool
    winhttp_proxy_server_literal: str | None
    git_http_proxy: str | None
    git_https_proxy: str | None
    npm_proxy: str | None
    npm_https_proxy: str | None
    user_http_proxy: str | None
    user_https_proxy: str | None
    user_all_proxy: str | None
    user_no_proxy: str | None
    captured_at: str

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return asdict(self)

    @classmethod
    def from_json_dict(cls, blob: dict[str, Any]) -> ProxySnapshot:
        """Load from ``reports/proxy_guard_lkg.json`` (ignores unknown keys)."""
        return cls(
            proxy_enable=blob.get("proxy_enable"),
            proxy_server=blob.get("proxy_server"),
            proxy_override=blob.get("proxy_override"),
            auto_config_url=blob.get("auto_config_url"),
            auto_detect=blob.get("auto_detect"),
            winhttp_proxy=str(blob.get("winhttp_proxy") or ""),
            winhttp_direct_access=bool(blob.get("winhttp_direct_access", False)),
            winhttp_proxy_server_literal=blob.get("winhttp_proxy_server_literal"),
            git_http_proxy=blob.get("git_http_proxy"),
            git_https_proxy=blob.get("git_https_proxy"),
            npm_proxy=blob.get("npm_proxy"),
            npm_https_proxy=blob.get("npm_https_proxy"),
            user_http_proxy=blob.get("user_http_proxy"),
            user_https_proxy=blob.get("user_https_proxy"),
            user_all_proxy=blob.get("user_all_proxy"),
            user_no_proxy=blob.get("user_no_proxy"),
            captured_at=str(blob.get("captured_at") or ""),
        )


@dataclass(frozen=True)
class ProxyChangeEvent:
    """Registry-focused change notification (rich snapshots carry full :class:`ProxySnapshot`)."""

    previous_proxy_view: dict[str, Any]
    current_proxy_view: dict[str, Any]
    previous_full_snapshot: ProxySnapshot | None
    current_full_snapshot: ProxySnapshot | None


@dataclass(frozen=True)
class ProxyGuardPolicyDecision:
    """Policy outcome for one detected proxy configuration transition."""

    decision: GuardDecisionKind
    reason: str
    matched_rule: str | None
    rollback_allowed: bool
    rollback_required: bool

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return asdict(self)


@dataclass(frozen=True)
class RollbackPlan:
    """Describes HKCU (+ optional WinHTTP) restoration intended from ``ProxySnapshot``."""

    dry_run_requested: bool
    restore_wininet: bool
    restore_winhttp: bool
    would_restore_git_or_env: bool
    rationale: tuple[str, ...] = ()

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
            "dry_run_requested": self.dry_run_requested,
            "restore_wininet": self.restore_wininet,
            "restore_winhttp": self.restore_winhttp,
            "would_restore_git_or_env": self.would_restore_git_or_env,
            "rationale": list(self.rationale),
        }


@dataclass(frozen=True)
class RollbackResult:
    """Observed rollback attempt outcome (counts as audit root)."""

    status: Literal[
        "skipped_no_lkg",
        "skipped_not_blocked",
        "skipped_dry_run",
        "skipped_observe",
        "skipped_suppressed",
        "skipped_auto_rollback_disabled",
        "skipped_roll_back_disallowed",
        "executed_ok",
        "executed_partial",
        "error",
    ]
    detail: str
    wininet_audit: tuple[dict[str, Any], ...] = ()
    winhttp_audit: dict[str, Any] | None = None

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
            "status": self.status,
            "detail": self.detail,
            "wininet_audit": list(self.wininet_audit),
            "winhttp_audit": self.winhttp_audit,
        }


@dataclass(frozen=True)
class ProxyGuardAuditRecord:
    """Unified JSONL row for SOC / internal audit review."""

    schema_version: Literal[2]
    timestamp: str
    event: str
    before_snapshot: dict[str, Any]
    after_snapshot: dict[str, Any]
    attribution: dict[str, Any]
    policy_decision: dict[str, Any]
    rollback_plan: dict[str, Any]
    rollback_result: dict[str, Any]
    safety_notes: tuple[str, ...] = ("no_firewall_changes", "no_adapter_mutations")

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
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "event": self.event,
            "before_snapshot": _json_leaf(self.before_snapshot),
            "after_snapshot": _json_leaf(self.after_snapshot),
            "attribution": _json_leaf(self.attribution),
            "policy_decision": _json_leaf(self.policy_decision),
            "rollback_plan": _json_leaf(self.rollback_plan),
            "rollback_result": _json_leaf(self.rollback_result),
            "safety_notes": list(self.safety_notes),
        }


__all__ = [
    "ActorCandidate",
    "AttributionMode",
    "AttributionResult",
    "ConfidenceLevel",
    "GuardDecisionKind",
    "HeuristicAttributionConfidence",
    "HeuristicAttributionMethod",
    "HeuristicPipelineAttribution",
    "ProcessIdentity",
    "ProxyChangeEvent",
    "ProxyGuardAuditRecord",
    "ProxyGuardPolicyDecision",
    "ProxySnapshot",
    "RollbackPlan",
    "RollbackResult",
    "_json_leaf",
]
