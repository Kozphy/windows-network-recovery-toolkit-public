"""Credential-lure detection (``credential_request``).

Module responsibility:
    Detect messages that ask the recipient to enter, confirm, or "verify"
    account credentials — the core of credential phishing — without visiting
    any link. Link risk is scored separately by ``website_risk``.

Key invariants:
    * A sentence must contain a credential *object* (password, account,
      mailbox, MFA / verification code …), a credential *action* (verify,
      confirm, sign in, re-enter …) and a *lure cue* (expiry, suspension,
      unusual activity, "click the link") — a bare "password" mention or a
      routine "you can sign in at the portal" does not fire.
    * Sentences that are clearly protective ("we will never ask for your
      password", "do not share your code") or about subscriptions
      ("update your preferences / unsubscribe") are excluded. URLs are
      removed before matching so link text cannot trigger or suppress it.
    * The lure cue must be in the same sentence: a cue in a neighbouring
      sentence ("Account suspended." … "Confirm your password.") is missed
      (known false-negative pattern, kept visible in the adversarial set).
    * Signature / disclaimer blocks are ignored (``EmailText.active``).

Side effects:
    None.
"""

from __future__ import annotations

import re

from .models import EmailRiskConfig, EmailRiskEvidence
from .normalization import EmailText, clip
from .scoring import build_evidence

CREDENTIAL_OBJECT = re.compile(
    r"(?i:\b(?:passwords?|passcodes?|credentials?|log[-\s]?in\s+details|sign[-\s]?in\s+details|"
    r"mfa|2fa|two[-\s]factor|one[-\s]time\s+(?:code|password|passcode)|verification\s+code|"
    r"security\s+code|otp|mailbox|e-?mail\s+account|(?:microsoft|office)\s*365|outlook\s+account|"
    r"google\s+account|gmail\s+account|apple\s+id|account)\b)"
    r"|密碼|帳號|帳戶|信箱|驗證碼|登入資訊|認證碼"
)
CREDENTIAL_ACTION = re.compile(
    r"(?i:\b(?:verify|confirm|update|validate|re-?enter|enter|sign\s*in|log\s*in|"
    r"re-?authenticate|re-?activate|reactivate|unlock|restore|reset|retain|keep\s+using|"
    r"provide|submit|share)\b)"
    r"|驗證|確認|更新|重新登入|登入|重設|解鎖|恢復|提供|輸入"
)
LURE_CUE = re.compile(
    r"(?i:\b(?:expir(?:e[sd]?|ing|ation)|suspend(?:ed|ing)?|suspension|locked|deactivat\w*|"
    r"disabled|terminated|unusual\s+(?:sign[-\s]?in|activity|login)|suspicious\s+(?:sign[-\s]?in|"
    r"activity|login)|will\s+be\s+(?:closed|deleted|removed|blocked)|storage\s+(?:is\s+)?full|"
    r"quota|click\s+(?:here|below|the\s+(?:link|button))|link\s+below|button\s+below|"
    r"within\s+\d+\s*(?:hours?|hrs?|days?)|failure\s+to|avoid\s+(?:losing|interruption|suspension)|"
    r"pending\s+messages|undelivered)\b)"
    r"|到期|過期|停用|暫停|鎖定|異常|點擊|點選|連結|註銷|凍結|失效"
)
PROTECTIVE = re.compile(
    r"(?i:\b(?:will\s+never|would\s+never|never\s+(?:ask|request|share)|"
    r"(?:don'?t|do\s+not)\s+(?:share|give|send|disclose|reply\s+with)|if\s+you\s+did(?:\s+not|n'?t)\s+"
    r"request)\b)"
    r"|不會(?:要求|詢問|索取)|請勿(?:提供|分享|透露)|切勿(?:提供|分享|透露)"
)
NON_CREDENTIAL = re.compile(
    r"(?i:\b(?:unsubscribe|preferences|subscription|newsletter|mailing\s+list|opt[-\s]out)\b)"
    r"|取消訂閱|訂閱設定"
)
_URL_TEXT = re.compile(r"(?i:\b(?:https?://|www\.)\S+)")


def detect_credential_request(text: EmailText, config: EmailRiskConfig) -> list[EmailRiskEvidence]:
    """Return ``credential_request`` evidence when a credential lure sentence is present."""
    for segment in text.active():
        sentence = _URL_TEXT.sub(" ", segment.text)
        if PROTECTIVE.search(sentence) or NON_CREDENTIAL.search(sentence):
            continue
        obj = CREDENTIAL_OBJECT.search(sentence)
        action = CREDENTIAL_ACTION.search(sentence)
        cue = LURE_CUE.search(sentence)
        if obj and action and cue:
            return [
                build_evidence(
                    "credential_request",
                    observed=clip(segment.text),
                    source=segment.source,
                    detail=(
                        f"Asks the recipient to {action.group(0).lower()} "
                        f"'{obj.group(0).lower()}' under a '{cue.group(0).lower()}' lure."
                    ),
                    config=config,
                )
            ]
    return []
