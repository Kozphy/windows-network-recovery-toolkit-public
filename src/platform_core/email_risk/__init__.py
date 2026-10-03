"""Deterministic email / BEC / QR-phishing risk assessment (analysis only).

Parses ``.eml`` / RFC 822 / JSON fixtures inertly, extracts header,
identity, social-engineering, credential-lure, channel-migration, payment,
and QR-request signals, decodes QR codes from local image bytes (never
opened), sends every extracted or decoded URL through ``website_risk`` static
heuristics, correlates signals into attack chains, and applies an advisory
policy gate. Returns explainable evidence with an ordinal risk level. Never
sends, deletes, quarantines, visits, or follows anything.
"""

from .audit import AUDIT_SCHEMA_VERSION, build_audit_record
from .correlation import (
    DEFAULT_CORRELATION_RULES,
    FAMILY_PROFILES,
    CorrelationConfigError,
    assess_attack_chain,
)
from .engine import (
    DISCLAIMER,
    analyze_email,
    analyze_email_file,
    email_risk_payload,
    render_email_risk_text,
)
from .models import (
    CLASSIFIER_VERSION,
    POLICY_VERSION,
    RULESET_VERSION,
    SCHEMA_VERSION,
    AttackChainAssessment,
    AttackFamily,
    CorrelationRule,
    EmailRiskConfig,
    EmailRiskEvidence,
    EmailRiskLevel,
    EmailRiskResult,
    ParsedEmail,
    PolicyCondition,
    PolicyDecision,
    PolicyGateResult,
    PolicyRule,
    QrArtifact,
    QrPayload,
    UrlAssessment,
    UrlOrigin,
    VendorProfile,
    VerificationGuidance,
)
from .parser import (
    EmailParseError,
    load_email_source,
    parse_email_json,
    parse_eml_bytes,
    parse_eml_text,
)
from .policy import (
    DEFAULT_POLICY_RULES,
    VERIFICATION_INSTRUCTION,
    PolicyConfigError,
    evaluate_email_policy,
)
from .qr_decode import QrDecodeError, QrDecoder, decoder_available, default_qr_decoder
from .qr_risk import classify_payload, decode_qr_images, detect_qr_requests

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "CLASSIFIER_VERSION",
    "DEFAULT_CORRELATION_RULES",
    "DEFAULT_POLICY_RULES",
    "DISCLAIMER",
    "FAMILY_PROFILES",
    "POLICY_VERSION",
    "RULESET_VERSION",
    "SCHEMA_VERSION",
    "VERIFICATION_INSTRUCTION",
    "AttackChainAssessment",
    "AttackFamily",
    "CorrelationConfigError",
    "CorrelationRule",
    "EmailParseError",
    "EmailRiskConfig",
    "EmailRiskEvidence",
    "EmailRiskLevel",
    "EmailRiskResult",
    "ParsedEmail",
    "PolicyCondition",
    "PolicyConfigError",
    "PolicyDecision",
    "PolicyGateResult",
    "PolicyRule",
    "QrArtifact",
    "QrDecodeError",
    "QrDecoder",
    "QrPayload",
    "UrlAssessment",
    "UrlOrigin",
    "VendorProfile",
    "VerificationGuidance",
    "analyze_email",
    "analyze_email_file",
    "assess_attack_chain",
    "build_audit_record",
    "classify_payload",
    "decode_qr_images",
    "decoder_available",
    "default_qr_decoder",
    "detect_qr_requests",
    "email_risk_payload",
    "evaluate_email_policy",
    "load_email_source",
    "parse_email_json",
    "parse_eml_bytes",
    "parse_eml_text",
    "render_email_risk_text",
]
