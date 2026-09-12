"""WinINET proxy state machine — audit-grade transition classification.

Module responsibility:
    Normalize WinINET proxy snapshots, classify full before/after transitions, build
    explainable evidence events, coalesce rapid flapping, and detect reverter loop patterns.

System placement:
    Core classifier for ``proxy-watch``, ``proxy-replay``, and portfolio safety contracts.
    Consumed by ``watch.py`` and ``tests/test_proxy_state_transitions.py``.

Key invariants:
    * Classification uses **full before/after state**, never isolated field diffs alone.
    * When ``after.ProxyServer`` is empty, remote proxy labels are forbidden
      (see ``FORBIDDEN_CLASSIFICATIONS_WHEN_AFTER_SERVER_EMPTY``).
    * Registry writer identity requires proof tier T3+ (Sysmon/EventLog/Procmon) — not bundled here.
    * Reverter detection is correlation-only; it does not prove registry writer identity.

Side effects:
    None — pure functions over in-memory dicts.

Failure modes:
    Missing before/after yields ``ERROR_INSUFFICIENT_DATA``.
    Unparseable timestamps in coalescing may fall back to wall-clock ordering.

Audit Notes:
    Misclassification of empty-after as remote proxy is blocked by ``validate_classification_safety``.
    Verify with ``pytest tests/test_proxy_classifier_safety_contract.py``.
    Recovery: replay fixture via ``proxy-replay`` and compare ``transition_class`` to golden JSON.

Engineering Notes:
    Full-state classification prevents false remote-proxy labels when only ``ProxyEnable`` flips.
    See ``docs/adr/0007-proxy-transition-full-state-classification.md``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from src.proxy_guard.parser import parse_proxy_server


class ProxyMode(StrEnum):
    """Derived WinINET proxy operating mode from normalized registry fields.

    Values are assigned by ``normalize_proxy_state`` from ProxyEnable, ProxyServer,
    AutoConfigURL, and AutoDetect. ``INCONSISTENT`` indicates enabled-without-server or
    disabled-with-server — not a malware verdict.
    """

    DISABLED = "DISABLED"
    LOCALHOST_PROXY = "LOCALHOST_PROXY"
    REMOTE_PROXY = "REMOTE_PROXY"
    PAC_CONFIGURED = "PAC_CONFIGURED"
    AUTODETECT = "AUTODETECT"
    INCONSISTENT = "INCONSISTENT"
    UNKNOWN = "UNKNOWN"


class TransitionClass(StrEnum):
    """Machine-readable transition label for a single before/after WinINET snapshot pair.

    Used in audit JSONL, replay output, and control tests. Not equivalent to incident
    classification — map via ``build_explainable_classification``.
    """

    NO_CHANGE = "NO_CHANGE"
    PROXY_DISABLED = "PROXY_DISABLED"
    PROXY_SERVER_REMOVED = "PROXY_SERVER_REMOVED"
    PROXY_SERVER_REMOVED_PARTIAL = "PROXY_SERVER_REMOVED_PARTIAL"
    PROXY_DISABLED_AND_SERVER_REMOVED = "PROXY_DISABLED_AND_SERVER_REMOVED"
    LOCALHOST_PROXY_ENABLED = "LOCALHOST_PROXY_ENABLED"
    REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED = "REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED"
    PROXY_SERVER_CHANGED_TO_REMOTE = "PROXY_SERVER_CHANGED_TO_REMOTE"
    PROXY_ENABLED_WITH_NO_SERVER = "PROXY_ENABLED_WITH_NO_SERVER"
    PAC_CONFIGURED = "PAC_CONFIGURED"
    PAC_REMOVED = "PAC_REMOVED"
    AUTODETECT_ENABLED = "AUTODETECT_ENABLED"
    WININET_WINHTTP_MISMATCH = "WININET_WINHTTP_MISMATCH"
    LOCALHOST_PROXY_PORT_CHANGED = "LOCALHOST_PROXY_PORT_CHANGED"
    REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP = "REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP"
    ERROR_INSUFFICIENT_DATA = "ERROR_INSUFFICIENT_DATA"


class PrimaryClassification(StrEnum):
    """Interview-grade primary labels derived from full before/after state.

    Deliberately avoids accusatory malware semantics. ``REMOTE_PROXY_CONFIGURED`` must not
    appear when ``after.proxy_server`` is empty — enforced by ``validate_classification_safety``.
    """

    NO_CHANGE = "NO_CHANGE"
    LOCALHOST_PROXY_REMOVED = "LOCALHOST_PROXY_REMOVED"
    PROXY_REMOVED = "PROXY_REMOVED"
    PROXY_DISABLED_OR_REMOVED = "PROXY_DISABLED_OR_REMOVED"
    LOCALHOST_PROXY_CONFIGURED = "LOCALHOST_PROXY_CONFIGURED"
    LOCALHOST_PROXY_PORT_CHANGED = "LOCALHOST_PROXY_PORT_CHANGED"
    PROXY_SERVER_CHANGED_TO_REMOTE = "PROXY_SERVER_CHANGED_TO_REMOTE"
    REMOTE_PROXY_CONFIGURED = "REMOTE_PROXY_CONFIGURED"
    PAC_CONFIGURED = "PAC_CONFIGURED"
    PAC_REMOVED = "PAC_REMOVED"
    PROXY_ENABLED_INCONSISTENT = "PROXY_ENABLED_INCONSISTENT"
    WININET_WINHTTP_MISMATCH = "WININET_WINHTTP_MISMATCH"
    REVERTER_SUSPECTED = "REVERTER_SUSPECTED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


# Safety invariant: never classify as remote proxy when after.ProxyServer is empty.
# Enforced by validate_classification_safety and tests/test_proxy_classifier_safety_contract.py.
FORBIDDEN_CLASSIFICATIONS_WHEN_AFTER_SERVER_EMPTY: frozenset[str] = frozenset(
    {
        "REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED",
        "REMOTE_PROXY_CONFIGURED",
        "PROXY_SERVER_CHANGED_TO_REMOTE",
        "NON_LOOPBACK_PROXY_CONFIGURED",
        PrimaryClassification.REMOTE_PROXY_CONFIGURED.value,
        PrimaryClassification.PROXY_SERVER_CHANGED_TO_REMOTE.value,
    }
)


TRUSTED_DEV_TOOLS = frozenset({"node.exe", "node", "cursor.exe", "cursor", "code.exe", "vscode.exe"})

STANDARD_ATTRIBUTION_LIMITATIONS = [
    "Likely process / correlation only",
    "Registry writer proof unavailable",
    "Attribution requires Sysmon, Procmon, or EventLog registry write evidence",
]


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _server_empty(val: Any) -> bool:
    if val is None:
        return True
    return str(val).strip() == ""


def _parse_ts(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        normalized = str(ts).replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return None


def make_transition_event_id(
    timestamp_utc: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> str:
    """Build a deterministic 24-char hex event id from transition inputs.

    Args:
        timestamp_utc: ISO-8601 UTC timestamp for the observation.
        before: Raw before-state dict (any key alias accepted by ``normalize_proxy_state``).
        after: Raw after-state dict.

    Returns:
        First 24 hex chars of SHA-256 over sorted JSON of timestamp and states.

    Side effects:
        None.

    Engineering Notes:
        Deterministic for replay verification; distinct from ``new_event_id()`` UUIDs used
        for live-only rows.
    """
    payload = json.dumps(
        {"timestamp_utc": timestamp_utc, "before": before, "after": after},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


@dataclass
class ProxyWininetState:
    """Normalized comparable WinINET proxy snapshot.

    Attributes:
        proxy_enable: WinINET ProxyEnable (bool).
        proxy_server: ProxyServer string or None when empty.
        auto_config_url: PAC URL or None.
        auto_detect: AutoDetect flag or None if unknown.
        proxy_override: ProxyOverride string or None.
        parsed_host: Loopback host when localhost proxy; else None.
        parsed_port: Parsed localhost port when applicable.
        proxy_mode: ``ProxyMode`` value string from normalization.
        winhttp_direct_access: Optional WinHTTP direct-access flag for mismatch checks.
    """

    proxy_enable: bool
    proxy_server: str | None
    auto_config_url: str | None
    auto_detect: bool | None
    proxy_override: str | None
    parsed_host: str | None
    parsed_port: int | None
    proxy_mode: str
    winhttp_direct_access: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return asdict(self)


def normalize_proxy_state(raw: dict[str, Any] | None) -> ProxyWininetState:
    """Normalize registry-facing or fixture dict into a comparable WinINET state.

    Args:
        raw: Dict with keys such as ``ProxyEnable``, ``wininet_proxy_enabled``,
            ``ProxyServer``, ``wininet_proxy_server``, ``AutoConfigURL``, etc.
            None is treated as empty/disabled.

    Returns:
        ``ProxyWininetState`` with derived ``proxy_mode`` and parsed localhost port.

    Side effects:
        None.

    Notes:
        Malformed server while enabled yields ``INCONSISTENT`` mode — not remote proxy.
    """
    if raw is None:
        raw = {}
    enable_raw = raw.get("proxy_enable", raw.get("ProxyEnable", raw.get("wininet_proxy_enabled")))
    if enable_raw is None:
        enable = False
    elif isinstance(enable_raw, bool):
        enable = enable_raw
    else:
        try:
            enable = int(enable_raw) == 1
        except (TypeError, ValueError):
            enable = bool(enable_raw)

    server_raw = raw.get("proxy_server", raw.get("ProxyServer", raw.get("wininet_proxy_server")))
    server: str | None
    if server_raw is None or (isinstance(server_raw, str) and not server_raw.strip()):
        server = None
    else:
        server = str(server_raw).strip()

    pac = raw.get("auto_config_url", raw.get("AutoConfigURL", raw.get("wininet_auto_config_url")))
    pac_str = str(pac).strip() if pac not in (None, "") else None

    auto_det = raw.get("auto_detect", raw.get("AutoDetect"))
    if auto_det is None:
        auto_detect: bool | None = None
    elif isinstance(auto_det, bool):
        auto_detect = auto_det
    else:
        try:
            auto_detect = int(auto_det) == 1
        except (TypeError, ValueError):
            auto_detect = bool(auto_det)

    override_raw = raw.get("proxy_override", raw.get("ProxyOverride", raw.get("wininet_proxy_override")))
    override = str(override_raw).strip() if override_raw not in (None, "") else None

    winhttp = raw.get("winhttp_direct_access")
    if winhttp is None:
        winhttp_val: bool | None = None
    else:
        winhttp_val = bool(winhttp)

    parsed = parse_proxy_server(server)
    host = parsed.localhost_host if parsed.is_localhost_proxy else None
    port = parsed.localhost_port
    if port is None and raw.get("localhost_port") is not None:
        try:
            port = int(raw["localhost_port"])
        except (TypeError, ValueError):
            port = None

    if parsed.is_malformed and enable:
        mode = ProxyMode.INCONSISTENT
    elif not enable and _server_empty(server) and not pac_str and not auto_detect:
        mode = ProxyMode.DISABLED
    elif pac_str:
        mode = ProxyMode.PAC_CONFIGURED
    elif auto_detect and not enable and _server_empty(server):
        mode = ProxyMode.AUTODETECT
    elif enable and parsed.is_localhost_proxy and port:
        mode = ProxyMode.LOCALHOST_PROXY
    elif enable and not _server_empty(server) and not parsed.is_localhost_proxy:
        mode = ProxyMode.REMOTE_PROXY
    elif enable and _server_empty(server) and not pac_str:
        mode = ProxyMode.INCONSISTENT
    elif not enable and not _server_empty(server):
        mode = ProxyMode.INCONSISTENT
    else:
        mode = ProxyMode.UNKNOWN

    return ProxyWininetState(
        proxy_enable=enable,
        proxy_server=server,
        auto_config_url=pac_str,
        auto_detect=auto_detect,
        proxy_override=override,
        parsed_host=host,
        parsed_port=port,
        proxy_mode=str(mode),
        winhttp_direct_access=winhttp_val,
    )


def states_equal(a: ProxyWininetState, b: ProxyWininetState) -> bool:
    """Return whether two normalized states match on classification-relevant fields.

    Args:
        a: First normalized state.
        b: Second normalized state.

    Returns:
        True when enable, server, PAC URL, auto-detect, and override match.

    Side effects:
        None.
    """
    return (
        a.proxy_enable == b.proxy_enable
        and a.proxy_server == b.proxy_server
        and a.auto_config_url == b.auto_config_url
        and a.auto_detect == b.auto_detect
        and a.proxy_override == b.proxy_override
    )


def classify_transition(
    before_raw: dict[str, Any] | None,
    after_raw: dict[str, Any] | None,
    *,
    winhttp_mismatch: bool | None = None,
) -> TransitionClass:
    """Classify a WinINET proxy transition from full before/after state.

    Decision intent:
        Determine the single best ``TransitionClass`` for an observed registry snapshot
        pair — not malware intent or registry writer identity.

    Args:
        before_raw: Complete before snapshot (fixture or live dict).
        after_raw: Complete after snapshot.
        winhttp_mismatch: Optional override for WinINET-enabled + WinHTTP-direct mismatch.
            When None, inferred from ``after.winhttp_direct_access`` if present.

    Returns:
        ``TransitionClass`` label. ``ERROR_INSUFFICIENT_DATA`` when inputs are None.

    Side effects:
        None.

    Audit Notes:
        Must receive full before/after state. Enable-only diff without server removal
        yields ``PROXY_DISABLED``; enable-off plus server cleared yields
        ``PROXY_DISABLED_AND_SERVER_REMOVED`` (see
        ``tests/test_proxy_state_transitions.py::test_classification_uses_full_state``).
        Remote labels require non-empty non-loopback ``after.proxy_server``.

    Engineering Notes:
        Field-level diffs in ``wininet_change_diff`` are for display only — this function
        is authoritative for transition class.
    """
    if before_raw is None or after_raw is None:
        return TransitionClass.ERROR_INSUFFICIENT_DATA

    before = normalize_proxy_state(before_raw)
    after = normalize_proxy_state(after_raw)

    if states_equal(before, after):
        return TransitionClass.NO_CHANGE

    server_removed = not _server_empty(before.proxy_server) and _server_empty(after.proxy_server)
    enable_off = before.proxy_enable and not after.proxy_enable
    enable_on = not before.proxy_enable and after.proxy_enable
    pac_added = _server_empty(before.auto_config_url) and not _server_empty(after.auto_config_url)
    pac_removed = not _server_empty(before.auto_config_url) and _server_empty(after.auto_config_url)
    pac_changed = (
        not _server_empty(before.auto_config_url)
        and not _server_empty(after.auto_config_url)
        and before.auto_config_url != after.auto_config_url
    )
    autodetect_on = not before.auto_detect and bool(after.auto_detect)
    before_localhost = before.proxy_mode == ProxyMode.LOCALHOST_PROXY.value
    after_remote = after.proxy_mode == ProxyMode.REMOTE_PROXY.value
    localhost_to_remote = (
        before_localhost
        and after_remote
        and not _server_empty(after.proxy_server)
    )

    mismatch = winhttp_mismatch
    if mismatch is None and after.winhttp_direct_access is not None:
        mismatch = bool(after.proxy_enable and after.winhttp_direct_access)

    if enable_off and server_removed:
        return TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED

    if server_removed and after.proxy_enable:
        return TransitionClass.PROXY_SERVER_REMOVED_PARTIAL

    if server_removed and not after.proxy_enable:
        return TransitionClass.PROXY_SERVER_REMOVED

    if enable_off:
        return TransitionClass.PROXY_DISABLED

    if mismatch and after.proxy_enable:
        return TransitionClass.WININET_WINHTTP_MISMATCH

    if after.proxy_enable and _server_empty(after.proxy_server) and not after.auto_config_url:
        return TransitionClass.PROXY_ENABLED_WITH_NO_SERVER

    if after.proxy_enable and after.proxy_mode == ProxyMode.INCONSISTENT.value:
        return TransitionClass.PROXY_ENABLED_WITH_NO_SERVER

    if pac_removed:
        return TransitionClass.PAC_REMOVED

    if pac_added or pac_changed:
        return TransitionClass.PAC_CONFIGURED

    if autodetect_on:
        return TransitionClass.AUTODETECT_ENABLED

    if (
        before.proxy_mode == ProxyMode.LOCALHOST_PROXY.value
        and after.proxy_mode == ProxyMode.LOCALHOST_PROXY.value
        and before.parsed_port != after.parsed_port
        and before.parsed_port is not None
        and after.parsed_port is not None
    ):
        return TransitionClass.LOCALHOST_PROXY_PORT_CHANGED

    if enable_on and after.proxy_mode == ProxyMode.LOCALHOST_PROXY.value:
        return TransitionClass.LOCALHOST_PROXY_ENABLED

    if localhost_to_remote:
        return TransitionClass.PROXY_SERVER_CHANGED_TO_REMOTE

    if (
        after.proxy_enable
        and not _server_empty(after.proxy_server)
        and after.proxy_mode == ProxyMode.REMOTE_PROXY.value
    ):
        return TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED

    if after.proxy_mode == ProxyMode.PAC_CONFIGURED.value and not (pac_added or pac_changed):
        return TransitionClass.PAC_CONFIGURED

    return TransitionClass.ERROR_INSUFFICIENT_DATA


def _risk_for_transition(
    transition: TransitionClass,
    *,
    listener_trusted: bool = False,
    listener_unknown: bool = False,
) -> str:
    if transition == TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP:
        if listener_unknown:
            return "HIGH"
        if listener_trusted:
            return "MEDIUM"
        return "HIGH"
    mapping = {
        TransitionClass.NO_CHANGE: "INFO",
        TransitionClass.PROXY_DISABLED: "LOW",
        TransitionClass.PROXY_SERVER_REMOVED: "LOW",
        TransitionClass.PROXY_SERVER_REMOVED_PARTIAL: "LOW",
        TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED: "LOW",
        TransitionClass.LOCALHOST_PROXY_ENABLED: "MEDIUM",
        TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED: "HIGH",
        TransitionClass.PROXY_ENABLED_WITH_NO_SERVER: "MEDIUM",
        TransitionClass.PAC_CONFIGURED: "MEDIUM",
        TransitionClass.AUTODETECT_ENABLED: "LOW",
        TransitionClass.WININET_WINHTTP_MISMATCH: "MEDIUM",
        TransitionClass.LOCALHOST_PROXY_PORT_CHANGED: "MEDIUM",
        TransitionClass.PAC_REMOVED: "LOW",
        TransitionClass.PROXY_SERVER_CHANGED_TO_REMOTE: "HIGH",
        TransitionClass.ERROR_INSUFFICIENT_DATA: "LOW",
    }
    return mapping.get(transition, "MEDIUM")


def _confidence_for_transition(transition: TransitionClass, *, writer_proof: bool = False) -> float:
    if writer_proof:
        return 0.92
    base = {
        TransitionClass.NO_CHANGE: 1.0,
        TransitionClass.PROXY_DISABLED: 0.85,
        TransitionClass.PROXY_SERVER_REMOVED: 0.88,
        TransitionClass.PROXY_SERVER_REMOVED_PARTIAL: 0.88,
        TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED: 0.9,
        TransitionClass.LOCALHOST_PROXY_ENABLED: 0.72,
        TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED: 0.85,
        TransitionClass.PROXY_ENABLED_WITH_NO_SERVER: 0.75,
        TransitionClass.PAC_CONFIGURED: 0.8,
        TransitionClass.AUTODETECT_ENABLED: 0.78,
        TransitionClass.WININET_WINHTTP_MISMATCH: 0.7,
        TransitionClass.LOCALHOST_PROXY_PORT_CHANGED: 0.8,
        TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP: 0.65,
        TransitionClass.ERROR_INSUFFICIENT_DATA: 0.3,
    }
    return base.get(transition, 0.55)


def _proof_tier_for_transition(transition: TransitionClass, *, writer_proof: bool = False, listener: bool = False) -> str:
    if writer_proof:
        return "T3"
    if listener and transition in (
        TransitionClass.LOCALHOST_PROXY_ENABLED,
        TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP,
    ):
        return "T2"
    if transition == TransitionClass.NO_CHANGE:
        return "T0"
    return "T1"


def _policy_decision_for_risk(risk: str) -> str:
    if risk == "CRITICAL":
        return "REQUIRE_HUMAN_REVIEW"
    if risk == "HIGH":
        return "REQUIRE_HUMAN_REVIEW"
    if risk == "MEDIUM":
        return "ALERT"
    if risk == "LOW":
        return "OBSERVE"
    return "OBSERVE"


def _recommended_action(transition: TransitionClass) -> str:
    actions = {
        TransitionClass.NO_CHANGE: "observe — no WinINET proxy state change",
        TransitionClass.PROXY_DISABLED: "observe — proxy disabled during developer/tool session",
        TransitionClass.PROXY_SERVER_REMOVED: "observe — ProxyServer removed",
        TransitionClass.PROXY_SERVER_REMOVED_PARTIAL: (
            "observe — ProxyServer removed while ProxyEnable remained enabled"
        ),
        TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED: "observe — proxy disabled and server removed",
        TransitionClass.LOCALHOST_PROXY_ENABLED: (
            "alert — localhost proxy enabled; investigate listener process executable path and command line"
        ),
        TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED: (
            "require human review — remote or non-loopback proxy server configured"
        ),
        TransitionClass.PROXY_ENABLED_WITH_NO_SERVER: (
            "alert — ProxyEnable set without ProxyServer; inconsistent WinINET state"
        ),
        TransitionClass.PAC_CONFIGURED: "alert — PAC (AutoConfigURL) configured or changed",
        TransitionClass.PAC_REMOVED: "observe — PAC (AutoConfigURL) removed",
        TransitionClass.PROXY_SERVER_CHANGED_TO_REMOTE: (
            "require human review — proxy server changed to remote/non-loopback endpoint"
        ),
        TransitionClass.AUTODETECT_ENABLED: "observe — WinINET auto-detect enabled",
        TransitionClass.WININET_WINHTTP_MISMATCH: (
            "alert — WinINET proxy enabled while WinHTTP reports direct access"
        ),
        TransitionClass.LOCALHOST_PROXY_PORT_CHANGED: (
            "alert — localhost proxy port changed; verify listener correlation only"
        ),
        TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP: (
            "require human review — pattern suggests a proxy reverter or auto-reapply loop; "
            "this is correlation, not proof of registry write; collect Sysmon Event ID 13 or Procmon trace"
        ),
        TransitionClass.ERROR_INSUFFICIENT_DATA: "observe — insufficient state to classify transition",
    }
    return actions.get(transition, "observe — review proxy transition manually")


def _limitations_for_transition(transition: TransitionClass) -> list[str]:
    base = ["Registry writer proof unavailable"]
    extra: dict[TransitionClass, list[str]] = {
        TransitionClass.PROXY_SERVER_REMOVED_PARTIAL: [
            "This event shows removal of ProxyServer, not remote proxy configuration",
        ],
        TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED: [
            "This event shows proxy disable and server removal, not remote proxy configuration",
        ],
        TransitionClass.LOCALHOST_PROXY_ENABLED: [
            "Process was listening on the configured localhost proxy port (correlation only)",
        ],
        TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP: [
            "Pattern suggests a proxy reverter or auto-reapply loop",
            "This is correlation, not proof of registry write",
            "Collect Sysmon Event ID 13 or Procmon trace for registry writer proof",
            "Investigate listener process executable path and command line",
        ],
        TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED: [
            "Remote proxy configuration observed in registry state — verify business justification",
        ],
    }
    return base + extra.get(transition, [])


def _map_primary_classification(
    transition: TransitionClass,
    *,
    before: ProxyWininetState,
    after: ProxyWininetState,
) -> PrimaryClassification:
    before_localhost = before.proxy_mode == ProxyMode.LOCALHOST_PROXY.value
    server_removed = not _server_empty(before.proxy_server) and _server_empty(after.proxy_server)

    if transition == TransitionClass.NO_CHANGE:
        return PrimaryClassification.NO_CHANGE
    if transition == TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP:
        return PrimaryClassification.REVERTER_SUSPECTED
    if transition == TransitionClass.ERROR_INSUFFICIENT_DATA:
        return PrimaryClassification.INSUFFICIENT_DATA
    if transition == TransitionClass.WININET_WINHTTP_MISMATCH:
        return PrimaryClassification.WININET_WINHTTP_MISMATCH
    if transition == TransitionClass.LOCALHOST_PROXY_PORT_CHANGED:
        return PrimaryClassification.LOCALHOST_PROXY_PORT_CHANGED
    if transition == TransitionClass.PROXY_SERVER_CHANGED_TO_REMOTE:
        return PrimaryClassification.PROXY_SERVER_CHANGED_TO_REMOTE
    if transition == TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED:
        return PrimaryClassification.REMOTE_PROXY_CONFIGURED
    if transition in (TransitionClass.PAC_CONFIGURED,):
        return PrimaryClassification.PAC_CONFIGURED
    if transition == TransitionClass.PAC_REMOVED:
        return PrimaryClassification.PAC_REMOVED
    if transition == TransitionClass.PROXY_ENABLED_WITH_NO_SERVER:
        return PrimaryClassification.PROXY_ENABLED_INCONSISTENT
    if transition == TransitionClass.LOCALHOST_PROXY_ENABLED:
        return PrimaryClassification.LOCALHOST_PROXY_CONFIGURED
    if transition == TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED:
        return PrimaryClassification.PROXY_DISABLED_OR_REMOVED
    if transition == TransitionClass.PROXY_SERVER_REMOVED_PARTIAL and before_localhost:
        return PrimaryClassification.LOCALHOST_PROXY_REMOVED
    if transition in (
        TransitionClass.PROXY_SERVER_REMOVED,
        TransitionClass.PROXY_SERVER_REMOVED_PARTIAL,
    ) and server_removed:
        return PrimaryClassification.PROXY_REMOVED if not before_localhost else PrimaryClassification.LOCALHOST_PROXY_REMOVED
    if transition == TransitionClass.PROXY_DISABLED:
        return PrimaryClassification.PROXY_DISABLED_OR_REMOVED
    return PrimaryClassification.INSUFFICIENT_DATA


def _secondary_signals(
    *,
    before: ProxyWininetState,
    after: ProxyWininetState,
    transition: TransitionClass,
    listener: dict[str, Any] | None = None,
    health: dict[str, Any] | None = None,
    writer_proof: bool = False,
) -> list[str]:
    signals: list[str] = []
    before_localhost = before.proxy_mode == ProxyMode.LOCALHOST_PROXY.value
    server_removed = not _server_empty(before.proxy_server) and _server_empty(after.proxy_server)

    if before_localhost and server_removed:
        signals.append("LOCALHOST_PROXY_REMOVED")
    if transition == TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED and before_localhost:
        signals.append("LOCALHOST_PROXY_REMOVED")
    if transition == TransitionClass.PROXY_DISABLED:
        signals.append("PROXY_ENABLE_DISABLED")

    proc = None
    if listener:
        proc = listener.get("process") if isinstance(listener.get("process"), dict) else listener
    if after.proxy_mode == ProxyMode.LOCALHOST_PROXY.value:
        if proc and proc.get("name"):
            signals.append("LISTENER_PRESENT")
        elif health and health.get("tcp_listening") is False:
            signals.append("LISTENER_MISSING")
        else:
            signals.append("LISTENER_UNKNOWN")

    if health:
        ps = str(health.get("proxy_status") or "")
        if ps == "DEAD_LOCALHOST_PROXY" or (
            health.get("direct_probe_ok") and not health.get("proxy_probe_ok")
        ):
            signals.append("DIRECT_OK_PROXY_FAIL")
        if health.get("proxy_probe_ok") and not health.get("direct_probe_ok"):
            signals.append("PROXY_OK_DIRECT_FAIL")
        if not health.get("direct_probe_ok") and not health.get("proxy_probe_ok"):
            signals.append("BOTH_PATHS_FAIL")

    if writer_proof:
        signals.append("REGISTRY_WRITER_PROOF_PRESENT")
    else:
        signals.append("REGISTRY_WRITER_PROOF_UNAVAILABLE")

    return list(dict.fromkeys(signals))


def validate_classification_safety(
    *,
    after_proxy_server: Any,
    primary_classification: str,
    transition_class: str,
) -> list[str]:
    """Return safety contract violations for a classification pair.

    Args:
        after_proxy_server: Normalized or raw ProxyServer value after transition.
        primary_classification: ``PrimaryClassification`` value string.
        transition_class: ``TransitionClass`` value string.

    Returns:
        Empty list when safe; otherwise human-readable violation messages.

    Side effects:
        None.

    Audit Notes:
        Any non-empty return is a release-blocking regression in CI safety contracts.
        Recovery: fix classifier logic and re-run ``test_proxy_classifier_safety_contract``.
    """
    violations: list[str] = []
    if _server_empty(after_proxy_server):
        for forbidden in FORBIDDEN_CLASSIFICATIONS_WHEN_AFTER_SERVER_EMPTY:
            if forbidden in (primary_classification, transition_class):
                violations.append(
                    f"after_proxy_server is empty but classification is {forbidden}"
                )
    return violations


def build_explainable_classification(
    *,
    before_raw: dict[str, Any],
    after_raw: dict[str, Any],
    transition: TransitionClass,
    listener: dict[str, Any] | None = None,
    health: dict[str, Any] | None = None,
    writer_proof: bool = False,
) -> dict[str, Any]:
    """Build interview-grade explainable classifier output for a transition.

    Args:
        before_raw: Raw before snapshot.
        after_raw: Raw after snapshot.
        transition: Precomputed ``TransitionClass`` for the pair.
        listener: Optional listener/owner dict with ``process`` metadata.
        health: Optional health probe dict (``direct_probe_ok``, ``proxy_probe_ok``, etc.).
        writer_proof: Whether registry writer proof (Sysmon/E13) is available.

    Returns:
        Dict with ``primary_classification``, ``secondary_signals``, ``confidence``,
        ``why``, ``limitations``, ``recommended_next_checks``, ``unsafe_inferences_blocked``,
        and ``safety_violations``.

    Side effects:
        None.
    """
    before = normalize_proxy_state(before_raw)
    after = normalize_proxy_state(after_raw)
    primary = _map_primary_classification(transition, before=before, after=after)
    secondary = _secondary_signals(
        before=before,
        after=after,
        transition=transition,
        listener=listener,
        health=health,
        writer_proof=writer_proof,
    )
    confidence = _confidence_for_transition(transition, writer_proof=writer_proof)

    why: list[str] = []
    if before.proxy_server != after.proxy_server:
        why.append(
            f"Observed ProxyServer transition: {before.proxy_server or 'None'} -> {after.proxy_server or 'None'}"
        )
    if before.proxy_enable != after.proxy_enable:
        why.append(
            f"Observed ProxyEnable transition: {int(before.proxy_enable)} -> {int(after.proxy_enable)}"
        )
    if primary == PrimaryClassification.LOCALHOST_PROXY_REMOVED:
        why.append("Evidence indicates localhost proxy server removal, not remote proxy configuration.")
    if primary == PrimaryClassification.REVERTER_SUSPECTED:
        why.append("Repeated enable/disable pattern observed — correlation only without registry writer proof.")

    limitations = _limitations_for_transition(transition)
    next_checks: list[str] = []
    if "REGISTRY_WRITER_PROOF_UNAVAILABLE" in secondary:
        next_checks.append("Collect Sysmon Event ID 13, Security 4657, or Procmon registry write trace.")
    if "LISTENER_MISSING" in secondary:
        next_checks.append("Identify process bound to configured localhost port or confirm stale proxy config.")
    if primary in (
        PrimaryClassification.REMOTE_PROXY_CONFIGURED,
        PrimaryClassification.PROXY_SERVER_CHANGED_TO_REMOTE,
    ):
        next_checks.append("Verify business justification for non-loopback proxy endpoint.")

    blocked: list[str] = []
    if not writer_proof:
        blocked.append("Malware accusation blocked because registry writer proof is missing.")
        blocked.append("Process name treated as correlation only — not registry writer proof.")
    if _server_empty(after.proxy_server):
        blocked.append("Remote proxy configured inference blocked because after_proxy_server is empty.")

    return {
        "primary_classification": primary.value,
        "secondary_signals": secondary,
        "confidence": confidence,
        "confidence_semantics": "ordinal_not_probability",
        "why": why or ["Full before/after WinINET state compared — not isolated field diff."],
        "limitations": limitations,
        "recommended_next_checks": next_checks,
        "unsafe_inferences_blocked": blocked,
        "transition_class": str(transition),
        "safety_violations": validate_classification_safety(
            after_proxy_server=after.proxy_server,
            primary_classification=primary.value,
            transition_class=str(transition),
        ),
    }


def build_attribution(
    listener: dict[str, Any] | None = None,
    *,
    writer_proof: bool = False,
    writer_kind: str | None = None,
) -> dict[str, Any]:
    """Build process attribution block with explicit correlation limits.

    Args:
        listener: Listener or owner payload; may nest process under ``process`` key.
        writer_proof: True when Sysmon/EventLog/Procmon writer proof is present.
        writer_kind: ``eventlog``, ``sysmon``, or ``procmon`` when ``writer_proof`` is True.

    Returns:
        Attribution dict with ``kind`` (correlation/none/eventlog), process fields,
        ordinal ``confidence``, and ``limitations``.

    Side effects:
        None.

    Notes:
        Process name on port is correlation only — not registry writer proof without T4.
    """
    proc = None
    if listener:
        proc = listener.get("process") if isinstance(listener.get("process"), dict) else listener

    if writer_proof and writer_kind in ("eventlog", "sysmon", "procmon"):
        kind = writer_kind
        conf = 0.85
        limitations: list[str] = []
    elif proc:
        kind = "correlation"
        conf = 0.55
        limitations = list(STANDARD_ATTRIBUTION_LIMITATIONS)
    else:
        kind = "none"
        conf = 0.0
        limitations = list(STANDARD_ATTRIBUTION_LIMITATIONS)

    return {
        "kind": kind,
        "process_name": proc.get("name") if proc else None,
        "pid": proc.get("pid") if proc else None,
        "parent_process": proc.get("parent") or proc.get("parent_name") if proc else None,
        "executable_path": proc.get("exe") or proc.get("executable_path") if proc else None,
        "command_line": proc.get("cmdline") or proc.get("command_line") if proc else None,
        "confidence": conf,
        "limitations": limitations,
    }


def build_proxy_evidence_event(
    *,
    before_raw: dict[str, Any],
    after_raw: dict[str, Any],
    timestamp_utc: str | None = None,
    listener: dict[str, Any] | None = None,
    writer_proof: bool = False,
    writer_kind: str | None = None,
    winhttp_mismatch: bool | None = None,
    health: dict[str, Any] | None = None,
    transition_override: TransitionClass | None = None,
    coalesce_meta: dict[str, Any] | None = None,
    raw_sub_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build structured audit evidence for a proxy state transition.

    Args:
        before_raw: Complete before WinINET snapshot.
        after_raw: Complete after WinINET snapshot.
        timestamp_utc: Event timestamp; defaults to current UTC ISO-8601.
        listener: Optional port listener / owner metadata.
        writer_proof: Whether registry writer telemetry is available.
        writer_kind: Writer telemetry source when ``writer_proof`` is True.
        winhttp_mismatch: Optional WinHTTP mismatch override for ``classify_transition``.
        health: Optional path probe results for secondary signals.
        transition_override: Force a transition class (used by reverter replay).
        coalesce_meta: Coalescing metadata (``coalesced``, ``raw_sub_event_count``, etc.).
        raw_sub_events: Sub-events merged when coalescing.

    Returns:
        Evidence event dict suitable for JSONL append or replay output, including
        ``classification``, ``proof_tier``, ``policy_decision``, and ``event_id``.

    Side effects:
        None.

    Audit Notes:
        Output includes ``classification.safety_violations`` — must be empty for production
        narratives. Strip no ``limitations`` fields for committee reporting.
    """
    ts = timestamp_utc or _now_utc()
    before = normalize_proxy_state(before_raw)
    after = normalize_proxy_state(after_raw)
    transition = transition_override or classify_transition(
        before_raw,
        after_raw,
        winhttp_mismatch=winhttp_mismatch,
    )

    proc = None
    if listener:
        proc = listener.get("process") if isinstance(listener.get("process"), dict) else listener
    proc_name = (proc or {}).get("name", "")
    listener_trusted = str(proc_name).lower() in TRUSTED_DEV_TOOLS
    listener_unknown = bool(after.proxy_mode == ProxyMode.LOCALHOST_PROXY.value and not proc_name)

    risk = _risk_for_transition(
        transition,
        listener_trusted=listener_trusted,
        listener_unknown=listener_unknown,
    )
    confidence = _confidence_for_transition(transition, writer_proof=writer_proof)
    proof_tier = _proof_tier_for_transition(
        transition,
        writer_proof=writer_proof,
        listener=bool(listener),
    )

    attribution = build_attribution(listener, writer_proof=writer_proof, writer_kind=writer_kind)
    if proof_tier in ("T0", "T1", "T2") and attribution["kind"] == "correlation":
        attribution["limitations"] = list(STANDARD_ATTRIBUTION_LIMITATIONS)

    evidence_lines: list[str] = []
    if before.proxy_server != after.proxy_server:
        evidence_lines.append(
            f"ProxyServer: {before.proxy_server or 'None'} -> {after.proxy_server or 'None'}"
        )
    if before.proxy_enable != after.proxy_enable:
        evidence_lines.append(
            f"ProxyEnable: {int(before.proxy_enable)} -> {int(after.proxy_enable)}"
        )
    if listener and proc_name:
        evidence_lines.append(
            f"Process was listening on the configured localhost proxy port: {proc_name} "
            "(Likely process / correlation only)"
        )

    event: dict[str, Any] = {
        "event_id": make_transition_event_id(ts, before.to_dict(), after.to_dict()),
        "timestamp_utc": ts,
        "before_state": before.to_dict(),
        "after_state": after.to_dict(),
        "transition_class": str(transition),
        "risk": risk,
        "confidence": confidence,
        "proof_tier": proof_tier,
        "attribution": attribution,
        "evidence": evidence_lines,
        "limitations": _limitations_for_transition(transition),
        "recommended_action": _recommended_action(transition),
        "policy_decision": _policy_decision_for_risk(risk),
        "classification": build_explainable_classification(
            before_raw=before_raw,
            after_raw=after_raw,
            transition=transition,
            listener=listener,
            health=health,
            writer_proof=writer_proof,
        ),
    }
    event["primary_classification"] = event["classification"]["primary_classification"]
    if coalesce_meta:
        event.update(coalesce_meta)
    if raw_sub_events:
        event["raw_sub_events"] = raw_sub_events
    return event


def merge_coalesced_states(
    sub_events: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Merge sub-events into one before/after pair preserving earliest before and latest after.

    Args:
        sub_events: Ordered list of raw or coalesced sub-events with before/after keys.

    Returns:
        Tuple of (before_dict, after_dict, raw_sub_event_summaries).

    Side effects:
        None.
    """
    if not sub_events:
        return {}, {}, []
    first = sub_events[0]
    last = sub_events[-1]
    before = first.get("before") or first.get("old_state") or first.get("before_state") or {}
    after = last.get("after") or last.get("new_state") or last.get("after_state") or {}
    raw: list[dict[str, Any]] = []
    for ev in sub_events:
        raw.append(
            {
                "timestamp_utc": ev.get("timestamp_utc"),
                "before": ev.get("before") or ev.get("old_state"),
                "after": ev.get("after") or ev.get("new_state"),
                "changed_fields": ev.get("changed_fields"),
            }
        )
    return dict(before), dict(after), raw


def coalesce_proxy_events(
    events: list[dict[str, Any]],
    *,
    coalesce_window_ms: int = 1000,
) -> list[dict[str, Any]]:
    """Merge proxy change observations within a time window into single transitions.

    Args:
        events: Raw transition rows with ``timestamp_utc`` and before/after state.
        coalesce_window_ms: Maximum span in milliseconds to batch rapid flapping.
            Clamped internally to 200ms–5000ms.

    Returns:
        List of transition dicts; multi-event batches include ``coalesced=True`` and
        classified evidence from ``build_proxy_evidence_event``.

    Side effects:
        None.

    Engineering Notes:
        Used by ``proxy-watch`` coalescing buffer and ``proxy-replay`` fixture tests.
    """
    if not events:
        return []

    window_sec = max(0.2, min(coalesce_window_ms / 1000.0, 5.0))
    sorted_events = sorted(events, key=lambda e: _parse_ts(str(e.get("timestamp_utc") or "")) or 0.0)

    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    batch_start: float | None = None

    for ev in sorted_events:
        ts = _parse_ts(str(ev.get("timestamp_utc") or ""))
        if not current:
            current = [ev]
            batch_start = ts
            continue
        if ts is not None and batch_start is not None and (ts - batch_start) <= window_sec:
            current.append(ev)
        else:
            batches.append(current)
            current = [ev]
            batch_start = ts
    if current:
        batches.append(current)

    out: list[dict[str, Any]] = []
    for batch in batches:
        if len(batch) == 1:
            ev = dict(batch[0])
            ev.setdefault("coalesced", False)
            ev.setdefault("coalesce_window_ms", coalesce_window_ms)
            ev.setdefault("raw_sub_event_count", 1)
            out.append(ev)
            continue

        before, after, raw_sub = merge_coalesced_states(batch)
        ts = batch[-1].get("timestamp_utc") or _now_utc()
        merged = build_proxy_evidence_event(
            before_raw=before,
            after_raw=after,
            timestamp_utc=str(ts),
            listener=batch[-1].get("owner") or batch[-1].get("listener"),
            coalesce_meta={
                "coalesced": True,
                "coalesce_window_ms": coalesce_window_ms,
                "raw_sub_event_count": len(batch),
            },
            raw_sub_events=raw_sub,
        )
        merged["before"] = before
        merged["after"] = after
        out.append(merged)
    return out


def detect_reverter_loop_pattern(
    transitions: list[dict[str, Any]],
    *,
    window_seconds: float = 300.0,
    min_cycles: int = 3,
) -> TransitionClass | None:
    """Detect repeated localhost enable/disable cycles (correlation only).

    Args:
        transitions: Classified or raw transition events with timestamps and states.
        window_seconds: Rolling window for cycle detection (default 300s).
        min_cycles: Minimum off→on→off cycles or enable-from-disabled events required.

    Returns:
        ``REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP`` when pattern matches; else None.

    Side effects:
        None.

    Audit Notes:
        Pattern detection does not identify registry writer or malware. Collect Sysmon E13
        before process-level remediation. Verify via ``proxy_enable_flapping_loop.jsonl`` replay.
    """
    if len(transitions) < min_cycles:
        return None

    timeline: list[tuple[float, bool, int | None]] = []
    for item in transitions:
        ts = _parse_ts(str(item.get("timestamp_utc") or ""))
        if ts is None:
            continue
        before = item.get("before_state") or item.get("before") or item.get("old_state") or {}
        after = item.get("after_state") or item.get("after") or item.get("new_state") or {}
        if not timeline:
            bst = normalize_proxy_state(before)
            timeline.append((ts, bst.proxy_enable, bst.parsed_port))
        ast = normalize_proxy_state(after)
        timeline.append((ts, ast.proxy_enable, ast.parsed_port))

    if len(timeline) < min_cycles + 1:
        return None

    timeline.sort(key=lambda x: x[0])
    newest = timeline[-1][0]
    windowed = [e for e in timeline if newest - e[0] <= window_seconds]
    if len(windowed) < min_cycles + 1:
        return None

    ports = {p for _, _, p in windowed if p is not None}
    if len(ports) != 1:
        return None
    port = next(iter(ports))

    full_cycles = 0
    for i in range(len(windowed) - 2):
        prev_off = not windowed[i][1]
        mid_on = windowed[i + 1][1]
        mid_port = windowed[i + 1][2]
        next_off = not windowed[i + 2][1]
        if prev_off and mid_on and mid_port == port and next_off:
            full_cycles += 1

    enable_from_disabled = 0
    for i in range(1, len(windowed)):
        if not windowed[i - 1][1] and windowed[i][1] and windowed[i][2] == port:
            enable_from_disabled += 1

    if full_cycles >= min_cycles or enable_from_disabled >= min_cycles:
        return TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP
    return None


@dataclass
class CoalescingBuffer:
    """Collect raw proxy observations and flush merged transitions.

    Attributes:
        coalesce_window_ms: Batch window passed to ``coalesce_proxy_events``.
    """

    coalesce_window_ms: int = 1000
    _pending: list[dict[str, Any]] = field(default_factory=list)
    _first_ts: float | None = None

    def add(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Add observation; flush merged events when coalesce window elapses.

        Args:
            event: Raw proxy change row with ``timestamp_utc`` and state fields.

        Returns:
            List of coalesced/classified events flushed when the window boundary is crossed;
            empty when the event is buffered.

        Side effects:
            Mutates internal ``_pending`` buffer only.
        """
        flushed: list[dict[str, Any]] = []
        ts = _parse_ts(str(event.get("timestamp_utc") or "")) or datetime.now(UTC).timestamp()
        if not self._pending:
            self._pending = [event]
            self._first_ts = ts
            return flushed

        window_sec = max(0.2, min(self.coalesce_window_ms / 1000.0, 5.0))
        if self._first_ts is not None and (ts - self._first_ts) <= window_sec:
            self._pending.append(event)
            return flushed

        flushed.extend(coalesce_proxy_events(self._pending, coalesce_window_ms=self.coalesce_window_ms))
        self._pending = [event]
        self._first_ts = ts
        return flushed

    def flush(self) -> list[dict[str, Any]]:
        """Flush any pending buffered events as coalesced transitions.

        Returns:
            Coalesced event list; empty when buffer is empty.

        Side effects:
            Clears internal pending buffer.
        """
        if not self._pending:
            return []
        merged = coalesce_proxy_events(self._pending, coalesce_window_ms=self.coalesce_window_ms)
        self._pending = []
        self._first_ts = None
        return merged


def transition_class_to_legacy_risk(transition: str) -> str:
    """Map transition class to legacy low/medium/high strings for backward-compatible diffs."""
    tc = TransitionClass(transition) if transition in TransitionClass.__members__.values() else None
    if tc is None:
        return "medium"
    risk = _risk_for_transition(tc)
    return risk.lower() if risk != "INFO" else "low"


def transition_class_to_legacy_reason(transition: str) -> str:
    """Map transition class to human reason string (audit-safe wording)."""
    try:
        tc = TransitionClass(transition)
    except ValueError:
        return "Proxy-related registry fields changed"
    if tc == TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED:
        return "Remote or non-loopback proxy server configured"
    if tc in (
        TransitionClass.PROXY_SERVER_REMOVED_PARTIAL,
        TransitionClass.PROXY_SERVER_REMOVED,
        TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED,
    ):
        return _recommended_action(tc)
    return _recommended_action(tc)


def new_event_id() -> str:
    """Return a random UUID string for non-deterministic live audit rows.

    Returns:
        UUID4 string.

    Side effects:
        None.

    Notes:
        Use ``make_transition_event_id`` for deterministic replay ids.
    """
    return str(uuid.uuid4())
