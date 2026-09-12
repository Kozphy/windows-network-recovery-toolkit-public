"""Browser-profile differential evidence models (privacy-preserving).

Module responsibility:
    Pydantic models and enums for browser-profile differential diagnostics
    (reliability tiers, classifications, site state, repair preview shapes).

System placement:
    Shared by adapters, classifier, runner, and repair preview.

Key invariants:
    Cookie *values*, Authorization headers, passwords, and history are never stored.
    Epistemic levels separate observation from proven cause.

Pipeline stages reflected:
    Observation → Hypothesis → Proof → Policy → Preview → Audit → Replay.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ReliabilityTier(StrEnum):
    """Ordinal evidence reliability from assertion (T0) to controlled proof (T4)."""

    T0_ASSERTION = "T0_ASSERTION"
    T1_STATIC_CONFIG = "T1_STATIC_CONFIG"
    T2_RUNTIME_CORROBORATION = "T2_RUNTIME_CORROBORATION"
    T3_CONTROLLED_REPRO = "T3_CONTROLLED_REPRO"
    T4_PROOF = "T4_PROOF"


class EpistemicLevel(StrEnum):
    """Confidence tier from raw observation to proven cause."""

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    PROBABLE_CAUSE = "probable_cause"
    PROVEN_CAUSE = "proven_cause"


class BrowserDiffClassification(StrEnum):
    """Triage labels for browser-profile differential findings.

    Labels describe observational categories — not malware attributions or
    security verdicts.  Operators should follow ``recommended_next_steps``
    rather than treating any label as confirmed root cause.
    """

    OS_NETWORK_OK_BROWSER_PROFILE_FAIL = "OS_NETWORK_OK_BROWSER_PROFILE_FAIL"
    SITE_DATA_OR_COOKIE_LOOP = "SITE_DATA_OR_COOKIE_LOOP"
    SERVICE_WORKER_INTERFERENCE = "SERVICE_WORKER_INTERFERENCE"
    EXTENSION_BLOCKING = "EXTENSION_BLOCKING"
    PROFILE_PROXY_OR_DOH_MISMATCH = "PROFILE_PROXY_OR_DOH_MISMATCH"
    BROWSER_POLICY_INTERFERENCE = "BROWSER_POLICY_INTERFERENCE"
    BROWSER_TLS_OR_CERTIFICATE_INTERFERENCE = "BROWSER_TLS_OR_CERTIFICATE_INTERFERENCE"
    ANTI_BOT_SESSION_STATE = "ANTI_BOT_SESSION_STATE"
    AUTHENTICATION_REDIRECT_LOOP = "AUTHENTICATION_REDIRECT_LOOP"
    BROWSER_PROFILE_CORRUPTION = "BROWSER_PROFILE_CORRUPTION"
    RAW_NETWORK_FAILURE = "RAW_NETWORK_FAILURE"
    SITE_SERVER_FAILURE = "SITE_SERVER_FAILURE"
    INSUFFICIENT_BROWSER_EVIDENCE = "INSUFFICIENT_BROWSER_EVIDENCE"
    NO_DIFF_BOTH_OK = "NO_DIFF_BOTH_OK"
    NO_DIFF_BOTH_FAIL = "NO_DIFF_BOTH_FAIL"


class EvidenceMeta(BaseModel):
    """Provenance envelope attached to every evidence record.

    Attributes:
        source: Collector or module that produced the evidence (e.g. ``"os_baseline"``).
        collected_at_utc: ISO-8601 UTC timestamp of collection.
        collection_method: Technique used (e.g. ``"socket_ssl_urllib"``).
        reliability_tier: Ordinal evidence quality tier.
        redaction_status: Whether sensitive fields were redacted before storage.
        error: Non-fatal error string encountered during collection, if any.
        admin_required: Whether elevated privileges were needed (and may have been absent).
    """

    source: str
    collected_at_utc: str
    collection_method: str
    reliability_tier: ReliabilityTier = ReliabilityTier.T1_STATIC_CONFIG
    redaction_status: Literal["none", "partial", "fully_redacted"] = "none"
    error: str | None = None
    admin_required: bool = False


class RawNetworkBaseline(BaseModel):
    """OS/protocol baseline with no browser cookies or extensions."""

    target_url: str
    dns_ok: bool = False
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    tcp_ok: bool = False
    tcp_error: str | None = None
    tls_ok: bool = False
    tls_error: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_sans: list[str] = Field(default_factory=list)
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    cert_thumbprint_sha256: str | None = None
    cert_chain_ok: bool | None = None
    http_status: int | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    timing_ms: float | None = None
    http_version: str | None = None
    wininet_proxy_enable: int | None = None
    wininet_proxy_server: str | None = None
    winhttp_proxy: str | None = None
    pac_configured: bool = False
    env_http_proxy: str | None = None
    env_https_proxy: str | None = None
    env_no_proxy: str | None = None
    direct_probe_ok: bool = False
    system_proxy_probe_ok: bool = False
    bot_challenge_hint: bool = False
    meta: EvidenceMeta | None = None
    limitations: list[str] = Field(default_factory=list)


class BrowserProfileEvidence(BaseModel):
    """Metadata for a single Chromium user profile directory.

    Cookie values, history, and passwords are never included.
    """

    browser: str
    profile_id: str
    profile_name: str = ""
    profile_path: str = ""
    browser_version: str = ""
    is_default: bool = False
    last_used_hint: str | None = None
    browser_open: bool | None = None
    meta: EvidenceMeta | None = None


class BrowserCookieMeta(BaseModel):
    """Cookie metadata only — never values."""

    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    expired: bool | None = None


class BrowserSiteStateEvidence(BaseModel):
    """Per-domain site-state metadata collected from a browser profile.

    Records cookie count, service-worker presence, HTTP-cache presence,
    and local-storage / IndexedDB presence for a single domain.
    Cookie *values* are never read, decrypted, or stored.
    """

    domain: str
    cookie_count: int = 0
    cookies_meta: list[BrowserCookieMeta] = Field(default_factory=list)
    service_worker_count: int = 0
    cache_present: bool = False
    cache_approx_bytes: int | None = None
    local_storage_present: bool = False
    indexed_db_present: bool = False
    meta: EvidenceMeta | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Cookie values were not read, decrypted, or logged.",
        ]
    )


class BrowserExtensionEvidence(BaseModel):
    """Metadata for a single installed browser extension.

    Records extension ID, name, enabled state, declared permissions, and a
    heuristic flag indicating whether the extension is proxy-capable.
    No extension secrets, tokens, or stored data are collected.
    """

    extension_id: str
    name: str = ""
    enabled: bool | None = None
    permissions: list[str] = Field(default_factory=list)
    update_url: str | None = None
    looks_like_proxy: bool = False
    meta: EvidenceMeta | None = None


class BrowserPolicyEvidence(BaseModel):
    """A single managed browser policy key relevant to network or privacy."""

    key: str
    value_summary: str = ""
    relevant_to: list[str] = Field(default_factory=list)
    meta: EvidenceMeta | None = None


class BrowserNetworkPreferenceEvidence(BaseModel):
    """Secure DNS and proxy preferences read from the browser's Preferences JSON.

    Reflects the profile-level settings that can cause network routing to differ
    between a normal profile and a private/ephemeral session.
    """

    secure_dns_mode: str | None = None
    secure_dns_templates: list[str] = Field(default_factory=list)
    proxy_mode: str | None = None
    proxy_server: str | None = None
    pac_url: str | None = None
    meta: EvidenceMeta | None = None


class HarRequestEvidence(BaseModel):
    """Privacy-safe summary of a single HAR request/response entry.

    Derived from a redacted HAR entry; cookie values and request bodies are
    replaced with ``[REDACTED]`` before this record is constructed.
    """

    url: str
    method: str = "GET"
    status: int = 0
    failed: bool = False
    blocked_by_client: bool = False
    redirect_url: str | None = None
    cookie_header_present: bool = False
    set_cookie_count: int = 0
    cache_indicated: bool = False
    service_worker_indicated: bool = False
    timing_ms: float | None = None
    error_text: str | None = None


class HarComparisonEvidence(BaseModel):
    """Structural differential produced by comparing normal vs private HAR archives.

    Contains only structural metadata (counts, status codes, redirect diffs,
    boolean cookie-presence flags).  No cookie values or response bodies are stored.
    """

    normal_entry_count: int = 0
    private_entry_count: int = 0
    status_mismatches: list[str] = Field(default_factory=list)
    redirect_diffs: list[str] = Field(default_factory=list)
    blocked_in_normal: list[str] = Field(default_factory=list)
    blocked_in_private: list[str] = Field(default_factory=list)
    cookie_presence_diff: str | None = None
    set_cookie_count_normal: int = 0
    set_cookie_count_private: int = 0
    normal_ok: bool | None = None
    private_ok: bool | None = None
    normal_final_status: int | None = None
    private_final_status: int | None = None
    auth_challenge_loop_hint: bool = False
    anti_bot_hint: bool = False
    cors_csp_hints: list[str] = Field(default_factory=list)
    timing_delta_ms: float | None = None
    privacy_redactions: list[str] = Field(default_factory=list)
    meta: EvidenceMeta | None = None


class BrowserRepairPreview(BaseModel):
    """Preview-only site-scoped repair plan.

    Generated by ``repair.build_repair_preview``; always has ``dry_run=True``.
    Applying the plan requires a typed confirmation token (``BROWSER_SITE_REPAIR_APPLY``).
    No browser state is mutated until the operator explicitly confirms via
    ``run_repair_apply``.
    """

    preview_id: str
    domain: str
    browser: str
    dry_run: bool = True
    actions: list[dict[str, Any]] = Field(default_factory=list)
    backup_plan: str = "Export non-secret site-state metadata before apply."
    requires_confirm_token: str = "BROWSER_SITE_REPAIR_APPLY"
    limitations: list[str] = Field(default_factory=list)


class BrowserDifferentialResult(BaseModel):
    """Top-level envelope returned by ``run_browser_diff``.

    Aggregates the OS-level baseline, HAR comparison, site-state metadata,
    extension and policy inventory, classification, and repair preview into a
    single governance-ready JSON artifact tagged ``wnt.browser_diff.v1``.
    """

    schema_version: str = "wnt.browser_diff.v1"
    target_url: str
    browser: str
    profiles_examined: list[BrowserProfileEvidence] = Field(default_factory=list)
    raw_network: RawNetworkBaseline | dict[str, Any] = Field(default_factory=dict)
    normal_session: dict[str, Any] = Field(default_factory=dict)
    private_session: dict[str, Any] = Field(default_factory=dict)
    site_state: BrowserSiteStateEvidence | dict[str, Any] | None = None
    extensions: list[BrowserExtensionEvidence] = Field(default_factory=list)
    policies: list[BrowserPolicyEvidence] = Field(default_factory=list)
    network_preferences: BrowserNetworkPreferenceEvidence | dict[str, Any] | None = None
    differences: list[str] = Field(default_factory=list)
    classification: BrowserDiffClassification = (
        BrowserDiffClassification.INSUFFICIENT_BROWSER_EVIDENCE
    )
    confidence: float = 0.0
    epistemic_level: EpistemicLevel = EpistemicLevel.OBSERVATION
    evidence: list[str] = Field(default_factory=list)
    counter_evidence: list[str] = Field(default_factory=list)
    unverified_assumptions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    repair_preview: BrowserRepairPreview | dict[str, Any] | None = None
    privacy_redactions: list[str] = Field(default_factory=list)
    audit_id: str = ""
    text_report: str = ""
    limitations: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict (all values JSON-safe)."""
        return self.model_dump(mode="json")
