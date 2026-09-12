"""JSON-backed allowlist for Proxy Guard remedial control (default-deny).

**Responsibility**
  Parse a static policy file and answer: given attributed TCP owner rows, is automated
  proxy remediation **allowed** for this endpoint session?

**System placement**
  Sits **after** attribution (``port_mapper`` / ``attribution_engine``) and **before**
  execution (``control``): ingestion of owner dicts → **policy evaluation** → serving
  an allow/deny decision to the orchestration layer.

**Key invariants**
  - **Default deny**: empty attribution or no whitelist hit yields ``allowed=False`` unless
    ``allow_when_attribution_empty`` is explicitly enabled.
  - **Deterministic**: same policy + same ``owner_rows`` → same ``PolicyDecision``.
  - **No network / DB**: evaluation is in-memory; loading reads one JSON file once per call.

**Consumers**
  ``src.proxy_guard.control`` and related orchestration call ``evaluate`` before any
  state-changing proxy reset.

**Engineering Notes**
  - Substring rules are intentionally simple (no regex) to keep policies auditable and
    predictable; trade-off is weaker expressiveness vs. operational clarity.
  - Exact matches are evaluated before substrings so administrators can carve out
    exceptions without substring shadowing surprises.

**Audit Notes**
  - Misconfiguration risk: overly broad substrings (e.g. ``"e"``) effectively allow
    everything—detect via policy review and integration tests.
  - Silent skipping: rows with missing/non-string ``process_name`` are ignored; detect by
    comparing attribution row count to evaluated row count in logs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable result of allowlist evaluation for one attribution snapshot.

    **Responsibility**
      Capture whether remedial control is permitted, *why*, and which rule (if any)
      satisfied the allowlist so downstream code can log and audit without re-parsing
      the policy.

    **Attributes**
      allowed: ``True`` only when the policy explicitly permits the current owners.
      reason: Stable machine-oriented code (e.g. ``exact_process_name_match``).
      matched_rule: Human-readable rule id (``exact:...`` / ``substring:...``) or policy
        flag name; ``None`` when denied without a match.
      primary_process_name: Lowercased name taken from the first owner row when useful
        for logging; may be ``None`` when attribution is empty.

    **Interaction**
      Produced exclusively by ``ProxyGuardPolicy.evaluate``; consumed by control and
      tests for assertions on ``allowed`` / ``reason``.
    """

    allowed: bool
    reason: str
    matched_rule: str | None
    primary_process_name: str | None


@dataclass(frozen=True)
class ProxyGuardPolicy:
    """Frozen allowlist configuration loaded from JSON for Proxy Guard.

    **Responsibility**
      Hold normalized whitelist entries and expose ``evaluate`` for attributed process
      rows resolved upstream.

    **Attributes**
      source_path: Absolute path to the policy file (audit trail).
      allowed_process_name_substrings: Case-insensitive substring checks against each
        owner ``process_name`` (e.g. ``chrome`` matches ``chrome.exe``).
      allowed_process_names_exact: Case-insensitive **full** executable name match after
        lowercasing (e.g. ``clash-win.exe``).
      allow_when_attribution_empty: If ``True``, an empty ``owner_rows`` list is treated
        as **allowed**; default behavior is deny when attribution produced no rows.
      trusted_exe_paths: Case-insensitive path prefixes for verified EventLog/Sysmon rows.
      allowed_autoconfig_url_substrings: Substrings that may appear in new ``AutoConfigURL``.

    **Interaction**
      Built only by ``load_proxy_guard_policy``; consumed by control flows that must gate
      risky automation.

    **Engineering Notes**
      Tuple immutability prevents accidental mutation after load; trade-off is rebuilding
      the object when policy hot-reload is added later.

    **observe_only_when_unknown_attribution**
      When ``True`` and no allowlist hits, emits an ``observe`` decision for rows where
      attribution lacked a deterministic process (**not** verified Sysmon/EventLog)—intended only
      for lab environments reviewing manual installs.

    **Audit Notes**
      Setting ``allow_when_attribution_empty=True`` removes attribution as a safety gate—
      use only when empty attribution is a known benign state and logged elsewhere.
    """

    source_path: Path
    allowed_process_name_substrings: tuple[str, ...]
    allowed_process_names_exact: tuple[str, ...]
    allow_when_attribution_empty: bool
    trusted_exe_paths: tuple[str, ...] = ()
    allowed_autoconfig_url_substrings: tuple[str, ...] = ()
    observe_only_when_unknown_attribution: bool = False

    def evaluate(self, owner_rows: list[dict[str, Any]]) -> PolicyDecision:
        """Decide whether attributed TCP owners satisfy the allowlist (default deny).

        **Decision intent**
          Prevent automated proxy remediation unless at least one attributed owner matches
          administrator-approved executable identifiers—balancing automation against mistaken
          disruption of unrelated processes.

        **Input assumptions**
          - ``owner_rows`` is ordered like upstream attribution (first row is primary).
          - Each row may include ``process_name`` (``str``) and ``pid``; other keys ignored.
          - Rows with missing, empty, or non-string ``process_name`` are **skipped** (not
            treated as deny by themselves; denial comes from no remaining matches).

        **Output guarantees**
          - Always returns ``PolicyDecision``; never raises for malformed row content.
          - If any row matches an exact rule, evaluation stops at first exact hit in row
            order; otherwise first substring hit wins.
          - ``primary_process_name`` reflects the first row’s ``process_name`` after
            lowercasing when that field is a non-empty string.

        **Constraints / limitations**
          - No PID validation, path checks, or signing—only executable **name** strings.
          - Substring rules cannot express exclusions (negation); narrow with exact rules.

        **Known failure modes**
          - Over-broad substrings allow unintended processes (policy review risk).
          - All rows skipped due to bad ``process_name`` → deny unless empty-list override.

        **Side effects**
          None (pure logic).

        **Idempotency**
          Repeated calls with identical ``owner_rows`` yield identical decisions; no
          counters or hidden state.

        Args:
            owner_rows: Attribution snapshots as dicts, typically ``[{"process_name": str,
                "pid": int}, ...]``.

        Returns:
            PolicyDecision: Allow/deny outcome with ``reason`` and optional ``matched_rule``.

        Example:
            >>> # Pseudocode: policy allows substring "chrome"
            >>> decision = policy.evaluate([{"process_name": "chrome.exe", "pid": 4}])
            >>> decision.allowed
            True
        """
        if not owner_rows:
            if self.allow_when_attribution_empty:
                return PolicyDecision(
                    allowed=True,
                    reason="no_attribution_allowed_by_policy_flag",
                    matched_rule="allow_when_attribution_empty",
                    primary_process_name=None,
                )
            return PolicyDecision(
                allowed=False,
                reason="no_attribution_default_deny",
                matched_rule=None,
                primary_process_name=None,
            )

        primary = owner_rows[0].get("process_name")
        primary_s = str(primary).lower() if isinstance(primary, str) else None

        for row in owner_rows:
            name = row.get("process_name")
            if not isinstance(name, str) or not name.strip():
                continue
            lowered = name.lower()

            for exact in self.allowed_process_names_exact:
                if lowered == exact.lower():
                    return PolicyDecision(
                        allowed=True,
                        reason="exact_process_name_match",
                        matched_rule=f"exact:{exact}",
                        primary_process_name=primary_s or lowered,
                    )

            for sub in self.allowed_process_name_substrings:
                if sub.lower() in lowered:
                    return PolicyDecision(
                        allowed=True,
                        reason="substring_process_name_match",
                        matched_rule=f"substring:{sub}",
                        primary_process_name=primary_s or lowered,
                    )

        return PolicyDecision(
            allowed=False,
            reason="no_whitelist_match_default_deny",
            matched_rule=None,
            primary_process_name=primary_s,
        )


def load_proxy_guard_policy(path: Path) -> ProxyGuardPolicy:
    """Load a Proxy Guard allowlist from JSON and return an immutable policy object.

    **Decision intent**
      Centralize schema validation so runtime evaluation never sees partially parsed or
      wrongly typed policy blobs.

    **Input data assumptions**
      - File is UTF-8 text containing a single JSON **object** at the root.
      - Optional keys (missing keys default to empty lists / ``False``):

        - ``allowed_process_name_substrings``: ``list[str]``
        - ``allowed_process_names_exact``: ``list[str]``
        - ``allow_when_attribution_empty``: ``bool``

    **Schema expectations**
      - Lists must contain only strings; unknown top-level keys are ignored.

    **Timezone / temporal data**
      None; policy files are static identifiers only.

    **Missing or bad data**
      - Malformed JSON → ``ValueError`` (wraps decode message).
      - Non-object root → ``ValueError``.
      - Wrong list element types → ``ValueError`` with field-specific message.

    **Side effects**
      Reads ``path`` from the local filesystem once; does not write.

    **Idempotency**
      Two loads of the same unchanged file produce equivalent ``ProxyGuardPolicy`` values;
      if the file changes between loads, results differ (not idempotent across mutation).

    **Performance**
      O(n) in total string entries; suitable for small operator-maintained policies.

    **Engineering Notes**
      ``path.resolve()`` stores a canonical path for audit logs; trade-off is absolute
      paths may differ on symlinked directories.

    **Audit Notes**
      - Corrupt JSON causes startup/load failure—detect in CI with schema tests.
      - Recovery: fix file on disk and reload (caller-dependent).

    Args:
        path: Path to the JSON policy file (must exist and be readable).

    Returns:
        ProxyGuardPolicy: Normalized, frozen policy ready for ``evaluate``.

    Raises:
        FileNotFoundError: If ``path`` does not exist or is unreadable (propagated from
            ``Path.read_text``).
        ValueError: If JSON is invalid, the root is not an object, or list entries are not
            strings.

    Example:
        >>> from pathlib import Path
        >>> pol = load_proxy_guard_policy(Path("policy.json"))
        >>> pol.evaluate([{"process_name": "chrome.exe", "pid": 1}]).allowed
        True
    """
    raw_text = path.read_text(encoding="utf-8")
    try:
        blob = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in policy file {path}: {exc}") from exc
    if not isinstance(blob, dict):
        raise ValueError(f"policy root must be an object: {path}")

    subs = blob.get("allowed_process_name_substrings") or []
    exact = blob.get("allowed_process_names_exact") or []
    if subs is not None and not isinstance(subs, list):
        raise ValueError("allowed_process_name_substrings must be a list")
    if exact is not None and not isinstance(exact, list):
        raise ValueError("allowed_process_names_exact must be a list")

    for item in subs:
        if not isinstance(item, str):
            raise ValueError("allowed_process_name_substrings entries must be strings")
    for item in exact:
        if not isinstance(item, str):
            raise ValueError("allowed_process_names_exact entries must be strings")

    allow_empty = bool(blob.get("allow_when_attribution_empty", False))

    trusted = blob.get("trusted_exe_paths") or []
    ac_subs = blob.get("allowed_autoconfig_url_substrings") or []
    if trusted is not None and not isinstance(trusted, list):
        raise ValueError("trusted_exe_paths must be a list")
    if ac_subs is not None and not isinstance(ac_subs, list):
        raise ValueError("allowed_autoconfig_url_substrings must be a list")
    for item in trusted:
        if not isinstance(item, str):
            raise ValueError("trusted_exe_paths entries must be strings")
    for item in ac_subs:
        if not isinstance(item, str):
            raise ValueError("allowed_autoconfig_url_substrings entries must be strings")

    return ProxyGuardPolicy(
        source_path=path.resolve(),
        allowed_process_name_substrings=tuple(str(x) for x in subs),
        allowed_process_names_exact=tuple(str(x) for x in exact),
        allow_when_attribution_empty=allow_empty,
        trusted_exe_paths=tuple(str(x) for x in trusted),
        allowed_autoconfig_url_substrings=tuple(str(x) for x in ac_subs),
        observe_only_when_unknown_attribution=bool(blob.get("observe_only_when_unknown_attribution", False)),
    )
