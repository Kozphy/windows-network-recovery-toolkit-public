"""Typed models for deterministic email / BEC risk assessment.

Module responsibility:
    Parsed-email representation, evidence objects, configuration, and the
    result envelope for ``email_risk``.

Key invariants:
    * ``EmailRiskEvidence`` extends ``WebsiteRiskEvidence`` so URL and email
      evidence share the same ``signal / observed / weight / detail`` shape.
    * ``confidence_band`` is ordinal; ``confidence`` is an uncalibrated
      evidence-support index in [0, 1] — neither is a probability.
    * Results carry ``limitations[]`` and never authorize action; policy
      decisions are recommendations (``advisory_only=True``).

Side effects:
    None.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field

from src.platform_core.website_risk.models import WebsiteRiskEvidence

SCHEMA_VERSION = "email_risk.v1"
RULESET_VERSION = "email_risk.rules.2026-09.pr3"
CLASSIFIER_VERSION = "email_risk.attack_chain.2026-09.pr3"
POLICY_VERSION = "email_risk.policy.2026-09.pr3"

DEFAULT_FREE_MAIL_DOMAINS: tuple[str, ...] = (
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.com.tw",
    "ymail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "yandex.com",
    "zoho.com",
    "qq.com",
    "163.com",
    "126.com",
)

DEFAULT_PROTECTED_DOMAINS: tuple[str, ...] = (
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "docusign.com",
    "dropbox.com",
)


class EmailRiskLevel(StrEnum):
    """Ordinal email risk level.

    ``UNKNOWN`` means the message could not be analyzed well enough to rank it;
    ``LOW`` means it was analyzed and little risk evidence was observed — not
    that the message is safe.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class SignalCategory(StrEnum):
    """Evidence family used for category-diversity gating in scoring."""

    SENDER_CONTEXT = "sender_context"
    HEADER_AUTHENTICATION = "header_authentication"
    IDENTITY = "identity"
    SOCIAL_ENGINEERING = "social_engineering"
    CREDENTIAL = "credential"
    CHANNEL_MIGRATION = "channel_migration"
    PAYMENT = "payment"
    QR = "qr"
    ARTIFACT = "artifact"
    URL = "url"


class EvidenceSource(StrEnum):
    """Where in the message a signal was observed."""

    HEADER_FROM = "header_from"
    HEADER_REPLY_TO = "header_reply_to"
    HEADER_RETURN_PATH = "header_return_path"
    HEADER_AUTHENTICATION = "header_authentication_results"
    DISPLAY_NAME = "display_name"
    EMAIL_SUBJECT = "email_subject"
    EMAIL_BODY = "email_body"
    EMAIL_URL = "email_url"
    ATTACHMENT = "attachment"
    INLINE_IMAGE = "inline_image"
    HTML_DATA_URI = "html_data_uri"


class UrlOrigin(StrEnum):
    """Where an extracted URL string came from (provenance, never visited)."""

    BODY_TEXT = "body_text"
    HTML_TEXT = "html_text"
    HTML_HREF = "html_href"
    QR_ATTACHMENT = "qr_attachment"
    QR_INLINE_IMAGE = "qr_inline_image"
    QR_HTML_DATA_URI = "qr_html_data_uri"


QR_URL_ORIGINS = frozenset(
    {UrlOrigin.QR_ATTACHMENT, UrlOrigin.QR_INLINE_IMAGE, UrlOrigin.QR_HTML_DATA_URI}
)


class AuthVerdict(StrEnum):
    """Normalized SPF / DKIM / DMARC verdict from receiver-stamped headers."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    POLICY = "policy"
    MISSING = "missing"


class EmailRiskEvidence(WebsiteRiskEvidence):
    """One explainable signal observation.

    Key fields:
        signal: Stable signal identifier (e.g. ``external_channel_migration``).
        observed: Short, redacted value that triggered the signal.
        weight: Contribution to the additive score (from the ruleset).
        source: Message location the value was taken from.
        category: Evidence family used for diversity gating.
        detail: Human-readable reason.
        observed_raw: Original (pre-normalization) line when matching needed
            Unicode folding or de-obfuscation; invisible characters are shown
            as ``<U+XXXX>``. Empty when identical to ``observed``.
    """

    source: EvidenceSource
    category: SignalCategory
    observed_raw: str = ""


class EmailAddress(BaseModel):
    """Parsed mailbox with optional display name."""

    display_name: str = ""
    address: str = ""

    @property
    def local_part(self) -> str:
        return self.address.rsplit("@", 1)[0].lower() if "@" in self.address else ""

    @property
    def domain(self) -> str:
        return self.address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in self.address else ""


class AttachmentMeta(BaseModel):
    """Attachment metadata only — content is never executed or persisted."""

    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0
    sha256: str = ""
    inline: bool = False


class ImagePart(BaseModel):
    """Image bytes held in memory for local QR decoding only.

    ``data`` is excluded from every dump/serialization so image content never
    reaches results, audit logs, or JSON output.
    """

    source: EvidenceSource
    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0
    sha256: str = ""
    data: bytes = Field(default=b"", exclude=True, repr=False)


class ExtractedUrl(BaseModel):
    """One normalized, de-duplicated URL with every place it appeared."""

    url: str
    host: str
    origins: list[UrlOrigin] = Field(default_factory=list)
    occurrences: int = 1


class AuthenticationSummary(BaseModel):
    """SPF / DKIM / DMARC verdicts parsed from receiver headers."""

    spf: AuthVerdict = AuthVerdict.MISSING
    dkim: AuthVerdict = AuthVerdict.MISSING
    dmarc: AuthVerdict = AuthVerdict.MISSING
    headers_present: bool = False
    authserv_id: str = ""


class ParsedEmail(BaseModel):
    """Inert, analysis-ready representation of one message."""

    source_format: Literal["eml", "json"] = "eml"
    parse_ok: bool = True
    parse_warnings: list[str] = Field(default_factory=list)
    from_address: EmailAddress | None = None
    sender: EmailAddress | None = None
    reply_to: list[EmailAddress] = Field(default_factory=list)
    return_path: str = ""
    to: list[EmailAddress] = Field(default_factory=list)
    cc: list[EmailAddress] = Field(default_factory=list)
    subject: str = ""
    message_id: str = ""
    body_text: str = ""
    body_html_text: str = ""
    urls: list[str] = Field(default_factory=list)
    url_records: list[ExtractedUrl] = Field(default_factory=list)
    rejected_url_count: int = 0
    received: list[str] = Field(default_factory=list)
    authentication_results: list[str] = Field(default_factory=list)
    received_spf: list[str] = Field(default_factory=list)
    authentication: AuthenticationSummary = Field(default_factory=AuthenticationSummary)
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    images: list[ImagePart] = Field(default_factory=list)

    def analyzable(self) -> bool:
        """Return True when there is enough content to rank risk at all."""
        return bool(
            self.from_address
            or self.subject.strip()
            or self.body_text.strip()
            or self.body_html_text.strip()
        )


class VendorProfile(BaseModel):
    """Known supplier with its legitimate sending domains."""

    name: str
    domains: list[str] = Field(default_factory=list)


class AttackFamily(StrEnum):
    """Attack pattern a message most strongly supports (a hypothesis, not a verdict)."""

    BEC_EXECUTIVE_FRAUD = "BEC_EXECUTIVE_FRAUD"
    QR_PHISHING = "QR_PHISHING"
    CHANNEL_MIGRATION_SCAM = "CHANNEL_MIGRATION_SCAM"
    VENDOR_PAYMENT_FRAUD = "VENDOR_PAYMENT_FRAUD"
    INVOICE_REDIRECTION = "INVOICE_REDIRECTION"
    CREDENTIAL_PHISHING = "CREDENTIAL_PHISHING"
    ACCOUNT_CHANGE_FRAUD = "ACCOUNT_CHANGE_FRAUD"
    UNKNOWN_SOCIAL_ENGINEERING = "UNKNOWN_SOCIAL_ENGINEERING"
    NONE = "NONE"


class CorrelationRule(BaseModel):
    """Declarative ``A + B (+ C …) → boost`` rule.

    ``requires`` is a conjunction of signal groups; a group is satisfied when
    any of its signals is present. ``level_floor`` optionally raises the final
    level to at least that value when the rule fires (itemized in the result).
    """

    rule_id: str = Field(min_length=1)
    requires: list[list[str]] = Field(min_length=1)
    delta: float = Field(ge=0.0, le=0.5)
    families: list[AttackFamily] = Field(default_factory=list)
    level_floor: EmailRiskLevel | None = None
    reason: str = ""


class PolicyDecision(StrEnum):
    """Advisory decision. None of these is executed by the toolkit.

    ``BLOCK_ACTION`` recommends that a person *not perform the requested
    action* (payment, account change, QR hand-over); it never deletes mail,
    disables accounts, or moves money.
    """

    ALLOW = "ALLOW"
    WARN = "WARN"
    HUMAN_VERIFY = "HUMAN_VERIFY"
    QUARANTINE_RECOMMENDED = "QUARANTINE_RECOMMENDED"
    BLOCK_ACTION = "BLOCK_ACTION"


class PolicyCondition(BaseModel):
    """All populated clauses must hold (AND).

    ``min_level``: risk level at or above (UNKNOWN never satisfies it).
    ``levels``: risk level exactly one of these.
    ``signal_groups``: AND of OR-groups over signal names.
    ``attack_chains``: selected attack family is one of these.
    An empty condition never matches (policies must say *when*).
    """

    min_level: EmailRiskLevel | None = None
    levels: list[EmailRiskLevel] = Field(default_factory=list)
    signal_groups: list[list[str]] = Field(default_factory=list)
    attack_chains: list[AttackFamily] = Field(default_factory=list)


class PolicyRule(BaseModel):
    """Configurable policy: condition → one or more advisory decisions."""

    policy_id: str = Field(min_length=1)
    description: str = ""
    when: PolicyCondition
    decisions: list[PolicyDecision] = Field(min_length=1)
    rationale: str = ""


class EmailRiskConfig(BaseModel):
    """Organization context and ruleset overrides (configuration-driven).

    Without ``organization_domains`` the engine cannot tell internal from
    external senders; affected signals degrade to "not evaluated" and a
    limitation is emitted rather than guessing.

    ``disabled_signals`` / ``correlation_enabled`` support tenant tuning and
    ablation studies; ``correlation_rules`` / ``policy_rules`` replace the
    built-in rule sets when provided (``None`` = defaults).
    """

    organization_domains: list[str] = Field(default_factory=list)
    organization_names: list[str] = Field(default_factory=list)
    executive_names: list[str] = Field(default_factory=list)
    vendors: list[VendorProfile] = Field(default_factory=list)
    protected_domains: list[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_DOMAINS))
    free_mail_domains: list[str] = Field(default_factory=lambda: list(DEFAULT_FREE_MAIL_DOMAINS))
    trusted_authserv_ids: list[str] = Field(default_factory=list)
    signal_weights: dict[str, float] = Field(default_factory=dict)
    max_urls_assessed: int = 20
    qr_decode: bool = True
    max_images_decoded: int = 10
    disabled_signals: list[str] = Field(default_factory=list)
    correlation_enabled: bool = True
    correlation_rules: list[CorrelationRule] | None = None
    policy_rules: list[PolicyRule] | None = None

    def merged(self, overlay: dict[str, Any] | None) -> EmailRiskConfig:
        """Return a copy with list fields extended and scalars replaced by ``overlay``."""
        if not overlay:
            return self.model_copy(deep=True)
        base = self.model_dump()
        for key, value in overlay.items():
            if key not in base:
                continue
            if isinstance(base[key], list) and isinstance(value, list):
                seen = list(base[key])
                for item in value:
                    if item not in seen:
                        seen.append(item)
                base[key] = seen
            elif isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        return EmailRiskConfig.model_validate(base)


class ScoreAdjustment(BaseModel):
    """Transparent correlation adjustment applied on top of additive weights."""

    rule_id: str
    delta: float
    signals: list[str] = Field(default_factory=list)
    reason: str = ""


QrDecodeStatus = Literal[
    "decoded",
    "no_qr_found",
    "decoder_unavailable",
    "decoding_disabled",
    "invalid_image",
    "too_large",
    "skipped_limit",
]
QrPayloadKind = Literal[
    "url",
    "messaging_invite",
    "wifi_config",
    "otp_secret",
    "crypto_payment",
    "email_address",
    "phone_or_sms",
    "contact_card",
    "text",
]


class QrPayload(BaseModel):
    """One decoded QR payload, redacted. Decoding never implies opening.

    ``value`` is the redacted display form. ``url`` is the canonical URL kept
    in memory only so it can be scored by ``website_risk``; it is excluded
    from serialization because query tokens may be credentials.
    """

    kind: QrPayloadKind
    value: str
    url: str = Field(default="", exclude=True, repr=False)
    platform: str = ""
    truncated: bool = False
    visited: Literal[False] = False


class QrArtifact(BaseModel):
    """Result of locally decoding one image part."""

    source: EvidenceSource
    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0
    sha256: str = ""
    decode_status: QrDecodeStatus
    payloads: list[QrPayload] = Field(default_factory=list)


class UrlAssessment(BaseModel):
    """One extracted URL with both analysis layers kept separate.

    Key fields:
        url: Redacted canonical URL (never visited).
        origins: Where the URL appeared (body text, HTML link, QR image ...).
        risk_level / score: The ``website_risk`` result, unchanged.
        website_risk_signals / website_risk_evidence: Raw evidence produced
            by the ``website_risk`` engine (the source of truth for URL risk).
        email_context_signals: Email-layer checks against the organization's
            own / vendor / protected domains (e.g. ``lookalike_domain``).
        signals: Union of both lists, kept for PR1 compatibility.
    """

    url: str
    risk_level: str
    score: float
    signals: list[str] = Field(default_factory=list)
    origins: list[UrlOrigin] = Field(default_factory=list)
    occurrences: int = 1
    website_risk_engine: str = "website_risk.assess_url_static"
    website_risk_assessment_id: str = ""
    website_risk_signals: list[str] = Field(default_factory=list)
    website_risk_evidence: list[WebsiteRiskEvidence] = Field(default_factory=list)
    email_context_signals: list[str] = Field(default_factory=list)
    fetched: Literal[False] = False


class FamilyScore(BaseModel):
    """Support for one attack family (sum of anchored evidence + rule deltas)."""

    family: AttackFamily
    support: float
    anchored: bool
    signals: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)


class AttackChainAssessment(BaseModel):
    """Which attack family the evidence supports, and why."""

    family: AttackFamily = AttackFamily.NONE
    confidence: float = 0.0
    supporting_signals: list[str] = Field(default_factory=list)
    supporting_rules: list[str] = Field(default_factory=list)
    candidates: list[FamilyScore] = Field(default_factory=list)
    rationale: str = ""


class WebsiteRiskContribution(BaseModel):
    """How much of the email score came from the website-risk layer."""

    signals: list[str] = Field(default_factory=list)
    weight: float = 0.0
    share_of_score: float = 0.0
    max_url_risk_level: str = "NONE"
    urls_assessed: int = 0
    urls_visited: Literal[0] = 0


class MatchedPolicy(BaseModel):
    """One policy rule that matched, with its decisions and rationale."""

    policy_id: str
    decisions: list[PolicyDecision]
    rationale: str = ""


class VerificationGuidance(BaseModel):
    """Out-of-band verification advice (never trusts contact data from the message)."""

    required: bool = False
    instruction: str = ""
    do_not_trust: list[str] = Field(default_factory=list)


class PolicyGateResult(BaseModel):
    """Advisory policy outcome; nothing here is executed automatically."""

    policy_version: str = POLICY_VERSION
    primary_decision: PolicyDecision = PolicyDecision.ALLOW
    decisions: list[PolicyDecision] = Field(default_factory=lambda: [PolicyDecision.ALLOW])
    matched_policies: list[MatchedPolicy] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    verification: VerificationGuidance = Field(default_factory=VerificationGuidance)
    advisory_only: Literal[True] = True
    automated_actions_taken: list[str] = Field(default_factory=list)


class EmailRiskResult(BaseModel):
    """Explainable email risk assessment (decision support, not a verdict)."""

    schema_version: str = SCHEMA_VERSION
    ruleset_version: str = RULESET_VERSION
    classifier_version: str = CLASSIFIER_VERSION
    analysis_id: str
    timestamp_utc: str
    source_type: Literal["email"] = "email"
    source_format: str = "eml"
    risk_level: EmailRiskLevel = EmailRiskLevel.UNKNOWN
    score: float = 0.0
    confidence_band: Literal["low", "medium", "high"] = "low"
    confidence: float = 0.0
    attack_chain: AttackFamily = AttackFamily.NONE
    attack_chain_detail: AttackChainAssessment = Field(default_factory=AttackChainAssessment)
    correlation_rules: list[str] = Field(default_factory=list)
    level_floor_rule: str = ""
    website_risk_contribution: WebsiteRiskContribution = Field(
        default_factory=WebsiteRiskContribution
    )
    policy: PolicyGateResult = Field(default_factory=PolicyGateResult)
    signals: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    evidence: list[EmailRiskEvidence] = Field(default_factory=list)
    adjustments: list[ScoreAdjustment] = Field(default_factory=list)
    authentication: AuthenticationSummary = Field(default_factory=AuthenticationSummary)
    sender_relationship: Literal["internal", "external", "unknown"] = "unknown"
    message_summary: dict[str, Any] = Field(default_factory=dict)
    email_signals: list[str] = Field(default_factory=list)
    url_assessments: list[UrlAssessment] = Field(default_factory=list)
    qr_artifacts: list[QrArtifact] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    automated_actions_taken: list[str] = Field(default_factory=list)
    evidence_hash: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def website_risk(self) -> list[dict[str, Any]]:
        """Compact per-URL view of the ``website_risk`` layer (raw engine output)."""
        return [
            {
                "url": a.url,
                "origins": [o.value for o in a.origins],
                "risk_level": a.risk_level,
                "score": a.score,
                "signals": list(a.website_risk_signals),
                "engine": a.website_risk_engine,
                "fetched": False,
            }
            for a in self.url_assessments
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict."""
        return self.model_dump(mode="json")
