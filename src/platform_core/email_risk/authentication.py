"""Header and sender-authentication signals.

Signals:
    ``from_reply_to_mismatch``, ``external_sender``, ``free_mail_sender``,
    ``spf_fail``, ``spf_softfail``, ``dkim_fail``, ``dmarc_fail``,
    ``authentication_missing``, ``suspicious_return_path``.

Key invariants:
    * Free-mail providers are neutral context (low weight, ``sender_context``
      category) — never malicious by themselves.
    * Passing SPF/DKIM/DMARC never *reduces* risk; it only means the sending
      domain was authenticated, not that the content is benign.
    * Verdicts come from receiver-stamped headers parsed by ``parser``; nothing
      is re-verified over DNS.

Side effects:
    None.
"""

from __future__ import annotations

from .domains import (
    is_free_mail,
    lookalike_match,
    registrable_domain,
    sender_relationship,
)
from .models import (
    AuthVerdict,
    EmailRiskConfig,
    EmailRiskEvidence,
    EvidenceSource,
    ParsedEmail,
)
from .privacy import mask_address
from .scoring import build_evidence


def _auth_signals(email: ParsedEmail, config: EmailRiskConfig) -> list[EmailRiskEvidence]:
    auth = email.authentication
    out: list[EmailRiskEvidence] = []
    src = EvidenceSource.HEADER_AUTHENTICATION
    if not auth.headers_present:
        out.append(
            build_evidence(
                "authentication_missing",
                observed="no Authentication-Results / Received-SPF",
                source=src,
                detail="Sender authentication cannot be evaluated from this message's headers.",
                config=config,
            )
        )
        return out
    if auth.spf in (AuthVerdict.FAIL, AuthVerdict.PERMERROR):
        out.append(
            build_evidence(
                "spf_fail",
                observed=f"spf={auth.spf.value}",
                source=src,
                detail="Receiving server reported SPF failure for the envelope sender.",
                config=config,
            )
        )
    elif auth.spf == AuthVerdict.SOFTFAIL:
        out.append(
            build_evidence(
                "spf_softfail",
                observed="spf=softfail",
                source=src,
                detail="Receiving server reported SPF softfail (sender not clearly authorized).",
                config=config,
            )
        )
    if auth.dkim in (AuthVerdict.FAIL, AuthVerdict.PERMERROR):
        out.append(
            build_evidence(
                "dkim_fail",
                observed=f"dkim={auth.dkim.value}",
                source=src,
                detail="DKIM signature failed verification at the receiving server.",
                config=config,
            )
        )
    if auth.dmarc == AuthVerdict.FAIL:
        out.append(
            build_evidence(
                "dmarc_fail",
                observed="dmarc=fail",
                source=src,
                detail="From-domain DMARC alignment failed at the receiving server.",
                config=config,
            )
        )
    return out


def _reply_to_mismatch(email: ParsedEmail, config: EmailRiskConfig) -> EmailRiskEvidence | None:
    if not email.from_address or not email.reply_to:
        return None
    from_reg = registrable_domain(email.from_address.domain)
    for reply in email.reply_to:
        reply_reg = registrable_domain(reply.domain)
        if reply_reg and from_reg and reply_reg != from_reg:
            detail = f"Replies go to {reply_reg}, not the From domain {from_reg}."
            if is_free_mail(reply.domain, config) and not is_free_mail(from_reg, config):
                detail += " Reply-To is a consumer mailbox."
            return build_evidence(
                "from_reply_to_mismatch",
                observed=f"from={from_reg} reply_to={mask_address(reply.address)}",
                source=EvidenceSource.HEADER_REPLY_TO,
                detail=detail,
                config=config,
            )
    return None


def _suspicious_return_path(
    email: ParsedEmail, config: EmailRiskConfig
) -> EmailRiskEvidence | None:
    if not email.from_address or not email.return_path or "@" not in email.return_path:
        return None
    rp_domain = email.return_path.rsplit("@", 1)[1].lower()
    rp_reg = registrable_domain(rp_domain)
    from_reg = registrable_domain(email.from_address.domain)
    if not rp_reg or rp_reg == from_reg or email.authentication.dmarc == AuthVerdict.PASS:
        return None
    reasons: list[str] = []
    if is_free_mail(rp_domain, config) and not is_free_mail(from_reg, config):
        reasons.append("envelope sender is a consumer mailbox")
    if email.authentication.spf in (AuthVerdict.FAIL, AuthVerdict.SOFTFAIL, AuthVerdict.PERMERROR):
        reasons.append(f"SPF {email.authentication.spf.value}")
    if lookalike_match(rp_domain, config):
        reasons.append("envelope domain resembles a protected domain")
    if not reasons:
        return None
    return build_evidence(
        "suspicious_return_path",
        observed=f"return_path={rp_reg} from={from_reg}",
        source=EvidenceSource.HEADER_RETURN_PATH,
        detail="Return-Path differs from From without DMARC pass: " + "; ".join(reasons) + ".",
        config=config,
    )


def detect_authentication_signals(
    email: ParsedEmail, config: EmailRiskConfig
) -> list[EmailRiskEvidence]:
    """Return header/authentication evidence for ``email``."""
    out: list[EmailRiskEvidence] = []
    domain = email.from_address.domain if email.from_address else ""
    if domain and config.organization_domains and sender_relationship(domain, config) == "external":
        out.append(
            build_evidence(
                "external_sender",
                observed=registrable_domain(domain),
                source=EvidenceSource.HEADER_FROM,
                detail="Sender domain is outside the configured organization domains.",
                config=config,
            )
        )
    if domain and is_free_mail(domain, config):
        out.append(
            build_evidence(
                "free_mail_sender",
                observed=registrable_domain(domain),
                source=EvidenceSource.HEADER_FROM,
                detail=(
                    "Sender uses a consumer mailbox provider. Neutral on its own; "
                    "relevant only alongside other signals."
                ),
                config=config,
            )
        )
    out.extend(_auth_signals(email, config))
    for item in (_reply_to_mismatch(email, config), _suspicious_return_path(email, config)):
        if item is not None:
            out.append(item)
    return out
