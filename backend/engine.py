"""Deterministic diagnosis and anomaly scoring for SaaS API requests.

This module sits between request validation (`backend.main`) and persistence
(`backend.db`). It converts lightweight telemetry signals into
human-readable root-cause decisions with risk labels.

Key invariants:
    - Rule evaluation is deterministic for identical inputs.
    - No file/database/network side effects occur in this module.
    - Output shape is stable for API consumers and tests.
"""

from dataclasses import dataclass

# Five consecutive strict increases require six chronological samples (five adjacent pairs).
_CONTINUOUS_GROWTH_STEPS = 5
_CONTINUOUS_GROWTH_MIN_SAMPLES = _CONTINUOUS_GROWTH_STEPS + 1


def _is_strictly_increasing(series: list[int], *, steps: int = _CONTINUOUS_GROWTH_STEPS) -> bool:
    """Return True when the last ``steps + 1`` samples each rise vs the prior sample."""
    need = steps + 1
    if len(series) < need:
        return False
    tail = series[-need:]
    return all(tail[i] < tail[i + 1] for i in range(steps))


@dataclass
class DiagnoseInput:
    """Normalized request signals used by rule-based diagnosis.

    Attributes:
        ping: Whether ICMP reachability to known public host succeeded.
        dns: Whether DNS resolution probe succeeded.
        https: Whether HTTPS probe succeeded.
        proxy: Whether proxy usage is detected/enabled.
        time_wait: Current count of sockets in TIME_WAIT state.
        established: Current count of sockets in ESTABLISHED state.
    """

    ping: bool
    dns: bool
    https: bool
    proxy: bool
    time_wait: int
    established: int


def detect_anomaly(
    current_time_wait: int,
    current_established: int,
    recent_metrics: list[dict],
) -> dict:
    """Detect short-term connection growth anomalies from recent metrics.

    Decision intent:
        Flag suspicious connection growth patterns that can indicate connection
        leaks or exhaustion trends.

    Input assumptions:
        - `recent_metrics` is newest-first.
        - Each metric row contains numeric `time_wait` and `established`.
        - Current values are non-negative integers.

    Output guarantees:
        - Always returns keys: `anomaly`, `reason`, and `signals`.
        - `signals` includes booleans for `rapid_growth`,
          `continuous_growth`, and `sudden_spike`.

    Side effects:
        None.

    Idempotency:
        Fully idempotent for identical inputs.

    Audit Notes:
        - What can go wrong: stale or sparse history can under-detect trends.
        - Detection: inspect `reason` and `signals` in diagnosis responses.
        - Recovery: gather additional samples and rerun diagnosis.

    Args:
        current_time_wait: Latest observed TIME_WAIT count.
        current_established: Latest observed ESTABLISHED count.
        recent_metrics: Recent persisted metrics (newest first).

    Returns:
        dict: Anomaly summary with machine-readable signal flags.

    Raises:
        KeyError: If expected fields are missing in `recent_metrics`.
        ValueError: If metric fields cannot be converted to integers.
    """
    if not recent_metrics:
        return {
            "anomaly": False,
            "reason": "Not enough history yet.",
            "signals": {
                "rapid_growth": False,
                "continuous_growth": False,
                "sudden_spike": False,
            },
        }

    prev = recent_metrics[0]
    prev_tw = int(prev["time_wait"])
    prev_est = int(prev["established"])

    rapid_growth = (prev_tw > 0 and current_time_wait > prev_tw * 2) or (
        prev_est > 0 and current_established > prev_est * 2
    )
    sudden_spike = (current_time_wait - prev_tw) > 1000 or (current_established - prev_est) > 1000

    # recent_metrics is newest-first; build chronological oldest→newest including current sample.
    history_for_trend = _CONTINUOUS_GROWTH_MIN_SAMPLES - 1
    tw_series = [int(m["time_wait"]) for m in recent_metrics[:history_for_trend]][::-1] + [
        current_time_wait,
    ]
    est_series = [int(m["established"]) for m in recent_metrics[:history_for_trend]][::-1] + [
        current_established,
    ]
    continuous_growth = _is_strictly_increasing(tw_series) or _is_strictly_increasing(est_series)

    anomaly = rapid_growth or sudden_spike or continuous_growth
    if anomaly:
        reason = "Rapid or continuous connection growth detected."
    else:
        reason = "No abnormal trend detected in recent metrics."

    return {
        "anomaly": anomaly,
        "reason": reason,
        "signals": {
            "rapid_growth": rapid_growth,
            "continuous_growth": continuous_growth,
            "sudden_spike": sudden_spike,
        },
    }


def classify_root_cause(data: DiagnoseInput, anomaly: dict) -> dict:
    """Classify likely root cause from probe outcomes and anomaly state.

    Decision intent:
        Provide an explainable next action for common Windows network failure
        patterns while preserving conservative risk defaults.

    Constraints and limitations:
        - Uses coarse-grained signals and simple precedence ordering.
        - Does not perform packet-level inspection or endpoint-specific tests.
        - Recommendations are advisory and require user/operator judgment.

    Known failure modes:
        - Multiple simultaneous issues may be collapsed into one top category.
        - Intermittent failures can produce unstable classifications across runs.

    Audit Notes:
        - What can go wrong: incorrect root-cause ordering under mixed signals.
        - Detection: compare returned recommendation with raw probe outputs.
        - Recovery: rerun probes, use monitor endpoint, and escalate to manual
          script-by-script validation.

    Args:
        data: Normalized signal payload for current diagnosis request.
        anomaly: Output from `detect_anomaly`.

    Returns:
        dict: Root-cause label, confidence band, recommendation, and risk.

    Raises:
        KeyError: If `anomaly["anomaly"]` is missing.
    """
    if not data.ping:
        return {
            "root_cause": "Network unreachable",
            "confidence": "high",
            "recommendation": "Check adapter/router/ISP path before running repair scripts.",
            "risk": "LOW",
        }

    if data.ping and not data.dns:
        return {
            "root_cause": "DNS issue",
            "confidence": "high",
            "recommendation": "Run reset_dns.bat and retest nslookup/curl/browser.",
            "risk": "LOW",
        }

    if data.proxy and not data.https:
        return {
            "root_cause": "Proxy misconfiguration",
            "confidence": "high",
            "recommendation": "Run reset_proxy.bat and reopen browser.",
            "risk": "LOW",
        }

    if data.ping and data.dns and not data.https:
        return {
            "root_cause": "HTTPS/TLS/firewall path issue",
            "confidence": "medium-high",
            "recommendation": "Check VPN/antivirus/firewall filters. If unclear, run one_click_fix.bat then restart.",
            "risk": "MEDIUM",
        }

    if data.time_wait > 5000 or anomaly["anomaly"]:
        return {
            "root_cause": "Connection exhaustion / leak trend",
            "confidence": "medium-high",
            "recommendation": "Restart network-heavy applications and review connection reuse in code (Session/pooling).",
            "risk": "LOW",
        }

    if data.ping and data.dns and data.https and not data.proxy:
        return {
            "root_cause": "Possible router/NAT/session intermittency",
            "confidence": "medium",
            "recommendation": "Monitor trends, try another network, and compare behavior over time.",
            "risk": "LOW",
        }

    return {
        "root_cause": "Mixed network state",
        "confidence": "medium",
        "recommendation": "Run one_click_fix.bat and restart, then collect new diagnostics.",
        "risk": "HIGH",
    }
