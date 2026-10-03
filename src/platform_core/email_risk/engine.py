"""Email risk engine: parse → detect → score → correlate → policy → explain.

Pipeline:
    ParsedEmail → EmailText → detectors (authentication, identity, social
    engineering, credential lure, channel migration, payment, QR requests) →
    local QR decode of image parts → URL targets (QR-decoded URLs + extracted
    links, canonicalized and deduplicated via ``website_risk.urls``) →
    ``website_risk.assess_url_static`` → ``score_evidence`` (additive weights +
    declarative correlation rules + level floors) → attack-family assessment →
    advisory policy gate → result with evidence, adjustments, attack chain,
    policy decisions, verification guidance, limitations, and evidence hash.

    Observation (evidence) → hypothesis (attack family) → policy (advisory
    decision) are kept in separate result fields; no stage executes anything.

Key invariants:
    * No network access: URLs are scored as strings; the URL assessor is
      injectable and the default never fetches. QR payloads are decoded from
      in-memory bytes and never opened.
    * ``website_risk`` is the only URL risk engine; this module adds only
      email context (organization lookalikes) and keeps it in a separate
      field so the origin of every URL signal stays visible.
    * No action is ever taken on the message or mailbox;
      ``automated_actions_taken`` is always empty.
    * Message bodies are not copied into results; evidence holds short,
      redacted phrases.

Side effects:
    ``analyze_email_file`` reads one local file. Nothing else.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from src.platform_core.website_risk.engine import assess_url_static
from src.platform_core.website_risk.models import WebsiteRiskLevel, WebsiteRiskResult
from src.platform_core.website_risk.urls import UrlNormalizationError, normalize_url

from .authentication import detect_authentication_signals
from .channel_migration import detect_channel_migration
from .correlation import active_rules, assess_attack_chain, validate_rules
from .credential_lure import detect_credential_request
from .domains import lookalike_match, normalize_domain, registrable_domain, sender_relationship
from .identity import describe_sender, detect_identity_signals
from .models import (
    QR_URL_ORIGINS,
    AttackFamily,
    EmailRiskConfig,
    EmailRiskEvidence,
    EmailRiskLevel,
    EmailRiskResult,
    EvidenceSource,
    ParsedEmail,
    QrArtifact,
    SignalCategory,
    UrlAssessment,
    UrlOrigin,
    WebsiteRiskContribution,
)
from .normalization import build_email_text, clip
from .parser import load_email_source
from .payment_intent import detect_payment_signals
from .policy import evaluate_email_policy, validate_policy_rules
from .privacy import mask_address, redact_free_text, redact_url, stable_hash
from .qr_decode import QrDecoder, default_qr_decoder
from .qr_risk import decode_qr_images, detect_qr_requests, qr_present_evidence, qr_url_origin
from .scoring import (
    PAYMENT_SIGNALS,
    QR_HANDOVER_SIGNALS,
    SIGNAL_CATEGORY,
    build_evidence,
    score_evidence,
    signal_weight,
)
from .social_engineering import detect_social_engineering_signals

UrlAssessor = Callable[[str], WebsiteRiskResult]
ConfidenceBand = Literal["low", "medium", "high"]

DISCLAIMER = (
    "This subsystem provides risk assessment and decision support and does not "
    "guarantee that an email is safe or malicious."
)

SIGNAL_LABELS: dict[str, str] = {
    "external_sender": "External sender",
    "free_mail_sender": "Consumer mailbox sender",
    "authentication_missing": "Authentication results missing",
    "from_reply_to_mismatch": "Reply-To differs from From",
    "spf_fail": "SPF fail",
    "spf_softfail": "SPF softfail",
    "dkim_fail": "DKIM fail",
    "dmarc_fail": "DMARC fail",
    "suspicious_return_path": "Suspicious Return-Path",
    "display_name_impersonation": "Display-name impersonation",
    "executive_impersonation": "Executive impersonation",
    "finance_team_impersonation": "Finance-team impersonation",
    "vendor_impersonation": "Vendor impersonation",
    "lookalike_domain": "Lookalike domain",
    "domain_typosquatting": "Typosquatted domain",
    "urgency": "Urgency",
    "secrecy_request": "Secrecy request",
    "authority_pressure": "Authority pressure",
    "credential_request": "Credential verification lure",
    "external_channel_migration": "Move to external chat channel",
    "payment_intent": "Payment intent",
    "wire_transfer_request": "Wire transfer request",
    "bank_account_change": "Bank account change",
    "invoice_fraud": "Invoice redirection pattern",
    "gift_card_request": "Gift card request",
    "crypto_payment_request": "Crypto payment request",
    "qr_code_present": "QR code decoded from image",
    "qr_code_scan_request": "Request to scan a QR code",
    "qr_code_return_request": "Request to send back a QR code",
    "messaging_group_qr_request": "Request for a messaging-group QR code",
    "suspicious_url": "Suspicious URL",
    "suspicious_qr_url": "Suspicious URL inside QR code",
}

_URL_LEVEL_FACTOR = {
    WebsiteRiskLevel.HIGH: 1.0,
    WebsiteRiskLevel.MEDIUM: 0.5,
    WebsiteRiskLevel.LOW: 0.25,
}

_QR_ONLY_LIMITATION = (
    "Deterministic English/Traditional Chinese lexical rules: paraphrased or "
    "image-based instructions (other than decoded QR payloads) can evade detection."
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class _UrlTarget:
    """One canonical URL to score, with every place it was seen."""

    url: str
    host: str
    origins: list[UrlOrigin] = field(default_factory=list)
    occurrences: int = 0
    qr_source: EvidenceSource | None = None

    @property
    def from_qr(self) -> bool:
        return any(o in QR_URL_ORIGINS for o in self.origins)


def _add_target(
    targets: dict[str, _UrlTarget],
    raw: str,
    origins: list[UrlOrigin],
    occurrences: int,
    qr_source: EvidenceSource | None = None,
) -> None:
    try:
        normalized = normalize_url(raw)
    except UrlNormalizationError:
        return
    target = targets.setdefault(
        normalized.dedupe_key, _UrlTarget(url=normalized.url, host=normalized.host)
    )
    target.origins.extend(o for o in origins if o not in target.origins)
    target.occurrences += occurrences
    if qr_source is not None and target.qr_source is None:
        target.qr_source = qr_source


def _url_targets(email: ParsedEmail, artifacts: list[QrArtifact]) -> list[_UrlTarget]:
    """QR-decoded URLs first, then message links; one entry per canonical URL."""
    targets: dict[str, _UrlTarget] = {}
    for artifact in artifacts:
        for payload in artifact.payloads:
            if payload.url:
                _add_target(
                    targets, payload.url, [qr_url_origin(artifact.source)], 1, artifact.source
                )
    if email.url_records:
        for record in email.url_records:
            _add_target(targets, record.url, list(record.origins), record.occurrences)
    else:
        for url in email.urls:
            _add_target(targets, url, [], 1)
    return list(targets.values())


def _url_evidence(
    signal: str,
    best: tuple[float, str, str, EvidenceSource],
    config: EmailRiskConfig,
) -> EmailRiskEvidence:
    factor, host, reason, source = best
    if signal == "suspicious_qr_url":
        detail = (
            f"URL decoded from a QR code ({source.value}) flagged by website_risk static "
            f"analysis ({reason}). QR decoded locally; URL was not visited."
        )
    else:
        detail = f"Linked host flagged by static analysis ({reason}). URL was not opened."
    return build_evidence(
        signal,
        observed=host,
        source=source,
        detail=detail,
        config=config,
        weight=round(signal_weight(signal, config) * factor, 3),
    )


def _assess_urls(
    targets: list[_UrlTarget], config: EmailRiskConfig, assessor: UrlAssessor
) -> tuple[list[UrlAssessment], list[EmailRiskEvidence]]:
    assessments: list[UrlAssessment] = []
    best: dict[str, tuple[float, str, str, EvidenceSource]] = {}
    for target in targets[: config.max_urls_assessed]:
        result = assessor(target.url)
        website_signals = [e.signal for e in result.evidence]
        factor = _URL_LEVEL_FACTOR.get(result.risk_level, 0.0) if website_signals else 0.0
        reason = (
            f"website_risk {result.risk_level.value}: {', '.join(website_signals)}"
            if website_signals
            else ""
        )
        host = normalize_domain(target.host)
        context_signals: list[str] = []
        look = lookalike_match(host, config)
        if look:
            context_signals.append(look[0])
            factor = 1.0
            reason = look[2]
        assessments.append(
            UrlAssessment(
                url=redact_url(target.url),
                risk_level=result.risk_level.value,
                score=result.score,
                signals=website_signals + context_signals,
                origins=target.origins,
                occurrences=target.occurrences,
                website_risk_assessment_id=result.assessment_id,
                website_risk_signals=website_signals,
                website_risk_evidence=list(result.evidence),
                email_context_signals=context_signals,
            )
        )
        if not factor:
            continue
        if target.from_qr:
            signal, source = "suspicious_qr_url", target.qr_source or EvidenceSource.ATTACHMENT
        else:
            signal, source = "suspicious_url", EvidenceSource.EMAIL_URL
        if signal not in best or factor > best[signal][0]:
            best[signal] = (factor, registrable_domain(host) or host, reason, source)
    evidence = [
        _url_evidence(signal, best[signal], config)
        for signal in ("suspicious_qr_url", "suspicious_url")
        if signal in best
    ]
    return assessments, evidence


def _dedupe(evidence: list[EmailRiskEvidence]) -> list[EmailRiskEvidence]:
    seen: set[str] = set()
    out: list[EmailRiskEvidence] = []
    for item in evidence:
        if item.signal not in seen:
            seen.add(item.signal)
            out.append(item)
    return out


def _redact_evidence(
    evidence: list[EmailRiskEvidence], *, show_identifiers: bool
) -> list[EmailRiskEvidence]:
    return [
        item.model_copy(
            update={
                "observed": redact_free_text(item.observed, show_identifiers=show_identifiers),
                "detail": redact_free_text(item.detail, show_identifiers=show_identifiers),
                "observed_raw": redact_free_text(
                    item.observed_raw, show_identifiers=show_identifiers
                ),
            }
        )
        for item in evidence
    ]


def _confidence_band(
    email: ParsedEmail, config: EmailRiskConfig, level: EmailRiskLevel
) -> ConfidenceBand:
    if level == EmailRiskLevel.UNKNOWN:
        return "low"
    completeness = sum(
        (
            email.parse_ok and not email.parse_warnings,
            email.authentication.headers_present,
            bool(config.organization_domains),
        )
    )
    if completeness == 3:
        return "high"
    return "medium" if completeness == 2 else "low"


def _recommendations(level: EmailRiskLevel, evidence: list[EmailRiskEvidence]) -> list[str]:
    signals = {e.signal for e in evidence}
    by_signal = {e.signal: e for e in evidence}
    recs: list[str] = []
    elevated = level in (EmailRiskLevel.HIGH, EmailRiskLevel.CRITICAL)
    if elevated or signals & PAYMENT_SIGNALS or "external_channel_migration" in signals:
        recs.append(
            "Verify the request out-of-band using an independently known corporate channel, "
            "such as a previously stored company phone number, official Teams/Slack account, "
            "or in-person confirmation. Do not use phone numbers, links, or chat IDs from this "
            "message (nor QR codes or Reply-To addresses it introduces); replying to this "
            "email is not verification."
        )
    if signals & PAYMENT_SIGNALS:
        recs.append(
            "Do not send money, change beneficiary details, or buy gift cards or crypto "
            "based on this email alone; follow the organization's payment-verification procedure."
        )
    if "external_channel_migration" in signals:
        platforms = by_signal["external_channel_migration"].observed
        recs.append(
            f"Do not move the conversation to {platforms} or share group invite links or "
            "QR codes until the requester is verified."
        )
    if signals & {"qr_code_scan_request", "suspicious_qr_url"}:
        recs.append(
            "Do not scan QR codes from this message with a phone: phone browsers usually "
            "bypass corporate link protection. Reach the service by typing an address you "
            "already know."
        )
    if signals & QR_HANDOVER_SIGNALS:
        recs.append(
            "Do not send, forward, or screenshot QR codes (LINE/WhatsApp group, login, or "
            "device-link codes) to the requester; a returned QR code can give them access to "
            "your account or group."
        )
    if elevated or signals & {
        "spf_fail",
        "dmarc_fail",
        "dkim_fail",
        "lookalike_domain",
        "domain_typosquatting",
    }:
        recs.append("Forward the message as an attachment to the security team for header review.")
    if level == EmailRiskLevel.UNKNOWN:
        recs.append(
            "The message could not be analyzed reliably; have a person review the original."
        )
    elif not recs:
        recs.append("No strong risk indicators were observed; normal caution still applies.")
    return recs


def _limitations(
    email: ParsedEmail,
    config: EmailRiskConfig,
    artifacts: list[QrArtifact],
    assessments: list[UrlAssessment],
) -> list[str]:
    out = [
        DISCLAIMER,
        _QR_ONLY_LIMITATION,
        "SPF/DKIM/DMARC verdicts are read from receiver-stamped headers, not re-verified; "
        "passing authentication does not mean the content is benign.",
        "URLs were assessed as strings via website_risk static heuristics; they were not opened.",
        "Registrable-domain logic approximates the Public Suffix List.",
        "confidence_band reflects evidence completeness (parse quality, auth headers, "
        "org context) — it is ordinal, not a probability.",
        "confidence is an uncalibrated attack-pattern support index (evidence weight, "
        "margin over other families, stage completeness); it is not a probability of "
        "maliciousness and has not been calibrated on real-world mail.",
        "attack_chain is a hypothesis derived from lexical and header evidence; it is not "
        "attribution and not proof of intent.",
        "Policy decisions are advisory recommendations for a person; nothing was blocked, "
        "moved, quarantined, or deleted.",
    ]
    if config.disabled_signals or not config.correlation_enabled:
        disabled = ", ".join(sorted(config.disabled_signals)) or "none"
        out.append(
            "Non-default ruleset (tuning/ablation): disabled signals: "
            f"{disabled}; correlation rules enabled: {config.correlation_enabled}."
        )
    if not config.organization_domains:
        out.append(
            "Organization domains not configured: internal/external status and "
            "role-impersonation checks are limited for non-consumer sender domains."
        )
    if email.attachments:
        out.append(
            "Attachments were inventoried by metadata only; apart from local QR decoding of "
            "image parts, content was not inspected (QR codes inside PDFs or documents were "
            "not decoded)."
        )
    statuses = {a.decode_status for a in artifacts}
    if artifacts:
        out.append(
            "QR codes were decoded locally from static image bytes (first frame only); "
            "decoded URLs were not visited and decoded payloads were not executed."
        )
    if "decoder_unavailable" in statuses:
        out.append(
            "QR decoder not installed (optional 'qr' extra: Pillow + zxing-cpp); image QR "
            "codes were not decoded."
        )
    if "decoding_disabled" in statuses:
        out.append("QR decoding was disabled by configuration; image QR codes were not decoded.")
    if statuses & {"too_large", "skipped_limit", "invalid_image"}:
        out.append("Some images were skipped (size/count limits or unreadable image data).")
    if any("url_shortener" in a.website_risk_signals for a in assessments):
        out.append("Shortened links were not resolved; their final destination is unknown.")
    if email.parse_warnings:
        out.append("The message had parsing issues; some fields may be missing or incomplete.")
    return out


def _message_summary(
    email: ParsedEmail, artifacts: list[QrArtifact], *, show_identifiers: bool
) -> dict[str, Any]:
    def addr(value: str) -> str:
        return value if show_identifiers else mask_address(value)

    payloads = [p for a in artifacts for p in a.payloads]
    return {
        "from": describe_sender(email.from_address, show_identifiers=show_identifiers),
        "reply_to": [addr(r.address) for r in email.reply_to],
        "return_path_domain": registrable_domain(email.return_path) if email.return_path else "",
        "subject": redact_free_text(clip(email.subject, 120), show_identifiers=show_identifiers),
        "message_id": email.message_id if show_identifiers else stable_hash(email.message_id),
        "to_count": len(email.to),
        "cc_count": len(email.cc),
        "url_count": len(email.urls),
        "rejected_url_count": email.rejected_url_count,
        "attachment_count": len(email.attachments),
        "attachment_types": sorted({a.content_type for a in email.attachments if a.content_type}),
        "image_count": len(email.images),
        "qr_decoded_count": len(payloads),
        "qr_url_count": sum(1 for p in payloads if p.url),
    }


def _website_risk_contribution(
    evidence: list[EmailRiskEvidence], assessments: list[UrlAssessment], score: float
) -> WebsiteRiskContribution:
    url_evidence = [e for e in evidence if e.category == SignalCategory.URL]
    weight = round(sum(e.weight for e in url_evidence), 3)
    raw_total = sum(e.weight for e in evidence)
    order = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    levels = [a.risk_level for a in assessments if a.risk_level in order]
    return WebsiteRiskContribution(
        signals=[e.signal for e in url_evidence],
        weight=weight,
        share_of_score=round(weight / raw_total, 3) if raw_total > 0 and score > 0 else 0.0,
        max_url_risk_level=max(levels, key=order.__getitem__) if levels else "NONE",
        urls_assessed=len(assessments),
    )


def _validate_config(cfg: EmailRiskConfig) -> None:
    known = SIGNAL_CATEGORY.keys()
    if cfg.correlation_rules is not None:
        validate_rules(cfg.correlation_rules, known)
    if cfg.policy_rules is not None:
        validate_policy_rules(cfg.policy_rules, known)
    unknown = sorted(set(cfg.disabled_signals) - set(known))
    if unknown:
        raise ValueError(f"disabled_signals: unknown signals {unknown}")


def _evidence_hash(result: EmailRiskResult, message_id: str) -> str:
    body = {
        "ruleset_version": result.ruleset_version,
        "classifier_version": result.classifier_version,
        "policy_version": result.policy.policy_version,
        "risk_level": result.risk_level.value,
        "score": result.score,
        "evidence": [e.model_dump(mode="json") for e in result.evidence],
        "adjustments": [a.model_dump(mode="json") for a in result.adjustments],
        "level_floor_rule": result.level_floor_rule,
        "attack_chain": result.attack_chain.value,
        "policy_decisions": [d.value for d in result.policy.decisions],
        "matched_policies": [m.policy_id for m in result.policy.matched_policies],
        "message_id": stable_hash(message_id),
    }
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def analyze_email(
    email: ParsedEmail,
    *,
    config: EmailRiskConfig | None = None,
    url_assessor: UrlAssessor | None = None,
    qr_decoder: QrDecoder | None = None,
    show_identifiers: bool = False,
) -> EmailRiskResult:
    """Assess one parsed email and return explainable evidence and a risk level.

    Args:
        email: Output of ``parser`` functions.
        config: Organization context / ruleset overrides (``qr_decode=False``
            disables image decoding).
        url_assessor: Injectable URL scorer; defaults to the network-free
            ``website_risk.assess_url_static``.
        qr_decoder: Injectable ``bytes -> [payload]`` decoder; defaults to the
            local Pillow + zxing-cpp decoder when installed.
        show_identifiers: When True, keep full addresses and Message-ID in
            the output (default masks them).

    Raises:
        CorrelationConfigError / PolicyConfigError / ValueError: configured
            rules, policies, or ``disabled_signals`` reference unknown signals.

    Side effects:
        None.
    """
    cfg = config or EmailRiskConfig()
    _validate_config(cfg)
    assessor = url_assessor or assess_url_static
    evidence: list[EmailRiskEvidence] = []
    url_assessments: list[UrlAssessment] = []
    artifacts: list[QrArtifact] = []
    if email.parse_ok:
        text = build_email_text(email)
        evidence.extend(detect_authentication_signals(email, cfg))
        evidence.extend(detect_identity_signals(email, text, cfg))
        evidence.extend(detect_social_engineering_signals(email, text, cfg))
        evidence.extend(detect_credential_request(text, cfg))
        evidence.extend(detect_channel_migration(text, cfg))
        evidence.extend(detect_payment_signals(text, cfg))
        evidence.extend(detect_qr_requests(text, cfg))
        decoder = qr_decoder or (default_qr_decoder() if email.images and cfg.qr_decode else None)
        artifacts = decode_qr_images(email, cfg, decoder)
        present = qr_present_evidence(artifacts, cfg)
        if present is not None:
            evidence.append(present)
        url_assessments, url_evidence = _assess_urls(_url_targets(email, artifacts), cfg, assessor)
        evidence.extend(url_evidence)
    disabled = set(cfg.disabled_signals)
    evidence = [
        e
        for e in _redact_evidence(_dedupe(evidence), show_identifiers=show_identifiers)
        if e.signal not in disabled
    ]
    breakdown = score_evidence(
        evidence,
        analyzable=email.parse_ok,
        rules=active_rules(cfg.correlation_rules, enabled=cfg.correlation_enabled),
    )
    chain = assess_attack_chain(
        evidence, breakdown.fired_rules, level=breakdown.level, score=breakdown.score
    )
    signals = [e.signal for e in evidence]
    policy = evaluate_email_policy(
        level=breakdown.level,
        signals=signals,
        attack_chain=chain.family,
        rules=cfg.policy_rules,
    )
    domain = email.from_address.domain if email.from_address else ""

    result = EmailRiskResult(
        analysis_id=f"er-{uuid.uuid4().hex[:12]}",
        timestamp_utc=_now(),
        source_format=email.source_format,
        risk_level=breakdown.level,
        score=breakdown.score,
        confidence_band=_confidence_band(email, cfg, breakdown.level),
        confidence=chain.confidence,
        attack_chain=chain.family,
        attack_chain_detail=chain,
        correlation_rules=[a.rule_id for a in breakdown.adjustments],
        level_floor_rule=breakdown.level_floor_rule,
        website_risk_contribution=_website_risk_contribution(
            evidence, url_assessments, breakdown.score
        ),
        policy=policy,
        signals=signals,
        categories=breakdown.categories,
        evidence=evidence,
        adjustments=breakdown.adjustments,
        authentication=email.authentication,
        sender_relationship=sender_relationship(domain, cfg),
        message_summary=_message_summary(email, artifacts, show_identifiers=show_identifiers),
        email_signals=[e.signal for e in evidence if e.category != SignalCategory.URL],
        url_assessments=url_assessments,
        qr_artifacts=artifacts,
        recommendations=_recommendations(breakdown.level, evidence),
        limitations=_limitations(email, cfg, artifacts, url_assessments),
        parse_warnings=list(email.parse_warnings),
    )
    result.evidence_hash = _evidence_hash(result, email.message_id)
    return result


def analyze_email_file(
    path: Path,
    *,
    config: EmailRiskConfig | None = None,
    url_assessor: UrlAssessor | None = None,
    qr_decoder: QrDecoder | None = None,
    show_identifiers: bool = False,
) -> EmailRiskResult:
    """Load ``.eml`` / RFC 822 / JSON fixture and analyze it.

    JSON fixtures may embed ``org_context``; it is merged on top of ``config``.

    Raises:
        EmailParseError: file unreadable, oversized, or invalid JSON.
    """
    base = config or EmailRiskConfig()
    email, context = load_email_source(path, trusted_authserv_ids=base.trusted_authserv_ids or None)
    return analyze_email(
        email,
        config=base.merged(context),
        url_assessor=url_assessor,
        qr_decoder=qr_decoder,
        show_identifiers=show_identifiers,
    )


def email_risk_payload(result: EmailRiskResult) -> dict[str, Any]:
    """Return the result as a governance-enveloped dict (preview-only, human decides)."""
    payload = attach_governance_envelope(
        result.to_dict(),
        primary_classification=f"EMAIL_RISK_{result.risk_level.value}",
        evidence_tier="observation",
        dry_run=True,
        requires_confirmation=True,
        executed=False,
        limitations=result.limitations,
    )
    gov = payload.get("governance")
    if isinstance(gov, dict):
        gov["execution_authority"] = "human_required"
    return payload


def render_email_risk_text(result: EmailRiskResult, *, ascii_only: bool = False) -> str:
    """Human-readable summary for terminals (``ascii_only`` for legacy code pages)."""
    mark = "[x]" if ascii_only else "\u2713"
    chain = result.attack_chain
    chain_line = f"Attack chain: {chain.value}"
    if chain not in (AttackFamily.NONE, AttackFamily.UNKNOWN_SOCIAL_ENGINEERING):
        chain_line += f" (support index {result.confidence:.2f}; uncalibrated, not a probability)"
    lines = [
        f"Risk: {result.risk_level.value}",
        chain_line,
        f"Score: {result.score:.2f} (ordinal; confidence band: {result.confidence_band})",
        f"Sender: {result.message_summary.get('from') or '(none)'} [{result.sender_relationship}]",
        f"Authentication: spf={result.authentication.spf.value} "
        f"dkim={result.authentication.dkim.value} dmarc={result.authentication.dmarc.value}",
        "",
        "Detected:",
    ]
    if not result.evidence:
        lines.append("  (no risk signals observed)")
    for item in result.evidence:
        label = SIGNAL_LABELS.get(item.signal, item.signal)
        lines.append(f"  {mark} {label} [{item.signal}, +{item.weight:.2f}] {item.observed}")
        lines.append(f"      {item.detail}")
    if result.adjustments:
        lines.append("")
        lines.append("Correlation rules:")
        for adj in result.adjustments:
            lines.append(f"  + {adj.rule_id} (+{adj.delta:.2f}): {adj.reason}")
        if result.level_floor_rule:
            lines.append(
                f"  Level floor: {result.level_floor_rule} raised the level to "
                f"{result.risk_level.value}."
            )
    lines.append("")
    lines.append("Policy (advisory; nothing was executed):")
    lines.extend(f"  {d.value}" for d in result.policy.decisions)
    if result.policy.matched_policies:
        matched = ", ".join(m.policy_id for m in result.policy.matched_policies)
        lines.append(f"  matched: {matched}")
    if result.policy.verification.required:
        lines.append("")
        lines.append("Verification:")
        lines.append("  Contact the claimed sender using an independently known corporate channel.")
        lines.append(f"  {result.policy.verification.instruction}")
        lines.append("  Do not trust:")
        lines.extend(f"    - {item}" for item in result.policy.verification.do_not_trust)
    if result.qr_artifacts:
        lines.append("")
        lines.append("QR images (decoded locally; nothing was opened):")
        for art in result.qr_artifacts:
            name = art.filename or art.content_type or "image"
            lines.append(f"  - {name} [{art.source.value}] {art.decode_status}")
            lines.extend(f"      {p.kind}: {p.value}" for p in art.payloads)
    if result.url_assessments:
        lines.append("")
        lines.append("Website-risk layer (URLs were not visited):")
        for ua in result.url_assessments:
            origins = ",".join(o.value for o in ua.origins) or "unknown"
            signals = ", ".join(ua.website_risk_signals) or "none"
            extra = (
                f"; email context: {', '.join(ua.email_context_signals)}"
                if ua.email_context_signals
                else ""
            )
            lines.append(f"  - {ua.url} [{origins}] {ua.risk_level} ({signals}{extra})")
    lines.append("")
    lines.append("Recommended next steps (no action was taken):")
    lines.extend(f"  - {rec}" for rec in result.recommendations)
    lines.append("")
    lines.append(
        f"Ruleset: {result.ruleset_version}  Classifier: {result.classifier_version}  "
        f"Evidence hash: {result.evidence_hash}"
    )
    lines.append(DISCLAIMER)
    return "\n".join(lines)


__all__ = [
    "DISCLAIMER",
    "analyze_email",
    "analyze_email_file",
    "email_risk_payload",
    "render_email_risk_text",
]
