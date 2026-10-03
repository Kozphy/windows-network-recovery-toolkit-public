"""Read-only verification checks (operational behavior, not intent).

Module responsibility:
    Emit ``VerificationResult`` rows that describe what was checked and whether signals support it.

Constraints:
    Checks validate reachability/configuration consistency — not registry-writer identity.

Audit Notes:
    * ``CONFIRMED`` means check passed, not malicious/benign intent.
"""

from __future__ import annotations

from typing import Any

from proxy_reasoning.constants import CASE_BROWSER_PROXY_PATH_ISSUE, CASE_WININET_PROXY_DRIFT
from proxy_reasoning.models import ProxyEntity, ProxySignal, VerificationResult


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "ok", "success"}
    return bool(value)


def _signal_map(signals: list[ProxySignal]) -> dict[str, Any]:
    return {s.name: s.value for s in signals}


def run_verification_checks(
    entity: ProxyEntity,
    signals: list[ProxySignal],
    *,
    proof_hints: dict[str, Any] | None = None,
) -> list[VerificationResult]:
    """Run safe verification checks from stored signals and optional proof hints.

    Proof hints may include pre-computed contrast results (e.g. from Proof Engine)
    without re-probing when replaying audit records.
    """
    smap = _signal_map(signals)
    hints = proof_hints or {}
    results: list[VerificationResult] = []

    # HTTPS proxy vs no-proxy contrast
    bypass = _truthy(smap.get("proxy_bypass_succeeded"))
    proxied_fail = _truthy(smap.get("proxied_path_failed"))
    if bypass or proxied_fail or hints.get("https_contrast"):
        contrast = hints.get("https_contrast") or {}
        bypass_ok = _truthy(contrast.get("bypass_ok", bypass))
        proxied_ok = _truthy(contrast.get("proxied_ok", not proxied_fail))
        if bypass_ok and not proxied_ok:
            status = "CONFIRMED"
            evidence = ["https_bypass_succeeds", "https_proxied_path_fails"]
        elif proxied_ok and bypass_ok:
            status = "INCONCLUSIVE"
            evidence = ["both_proxied_and_bypass_ok"]
        elif not bypass_ok and not proxied_ok:
            status = "REJECTED"
            evidence = ["neither_path_succeeded"]
        else:
            status = "INCONCLUSIVE"
            evidence = ["mixed_https_paths"]
        results.append(
            VerificationResult(
                check_id="https_proxy_vs_bypass",
                status=status,
                hypothesis_scope=CASE_BROWSER_PROXY_PATH_ISSUE,
                evidence=evidence,
                limitations=["Contrast confirms path behavior only, not registry writer intent."],
            ),
        )

    # WinINET vs WinHTTP divergence
    if entity.configuration_attributes.wininet_winhttp_divergent:
        results.append(
            VerificationResult(
                check_id="wininet_winhttp_divergence",
                status="CONFIRMED",
                hypothesis_scope=CASE_WININET_PROXY_DRIFT,
                evidence=["wininet_proxy_enabled", "winhttp_direct"],
                limitations=[
                    "Divergence is configuration observation, not proof of malicious change."
                ],
            ),
        )

    # Localhost listener existence
    if entity.network_attributes.listener_present is True:
        results.append(
            VerificationResult(
                check_id="localhost_listener_present",
                status="CONFIRMED",
                hypothesis_scope="CASE_LOCALHOST_PROXY_LISTENER",
                evidence=["listener_on_proxy_port"],
                limitations=[
                    "Listener presence does not prove the attributed process modified registry settings.",
                ],
            ),
        )
    elif (
        entity.network_attributes.is_loopback
        and entity.network_attributes.listener_present is False
    ):
        results.append(
            VerificationResult(
                check_id="localhost_listener_present",
                status="REJECTED",
                hypothesis_scope="CASE_LOCALHOST_PROXY_LISTENER",
                evidence=["loopback_proxy_configured", "no_listener"],
                limitations=[],
            ),
        )

    # Browser vs curl path
    curl_ok = _truthy(smap.get("curl_https_ok"))
    browser_fail = _truthy(smap.get("browser_https_failed"))
    if curl_ok and browser_fail:
        results.append(
            VerificationResult(
                check_id="browser_vs_curl_path",
                status="CONFIRMED",
                hypothesis_scope=CASE_BROWSER_PROXY_PATH_ISSUE,
                evidence=["curl_https_ok", "browser_https_failed"],
                limitations=["Does not identify root cause — only path divergence."],
            ),
        )

    # Firewall feedback — never CONFIRMED root cause without before/after
    if _truthy(smap.get("firewall_reset_helped")):
        before_fail = _truthy(smap.get("electron_app_failed_before"))
        status = "CONFIRMED" if before_fail else "INCONCLUSIVE"
        results.append(
            VerificationResult(
                check_id="firewall_reset_outcome",
                status=status,
                hypothesis_scope="CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION",
                evidence=["firewall_reset_helped"]
                + (["electron_app_failed_before"] if before_fail else []),
                limitations=[
                    "Post-hoc firewall relief does not prove firewall was root cause without before/after evidence.",
                ],
            ),
        )

    if not results:
        results.append(
            VerificationResult(
                check_id="none",
                status="UNVERIFIED",
                limitations=["No verification checks had sufficient signal input."],
            ),
        )
    return results
