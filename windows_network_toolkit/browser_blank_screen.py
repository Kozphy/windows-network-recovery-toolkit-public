"""Diagnose and remediate Edge/Chromium blank-screen (e.g. LinkedIn black UI).

Module responsibility:
    When origin HTTPS works but the browser shows a blank/black page (common
    on LinkedIn), correlate network path with Edge GPU/cache/service-worker
    state and offer a dry-run-default cache + hardware-acceleration cleanup.

System placement:
    CLI: ``browser-blank-screen`` (read-only diagnose; optional
    ``--with-fix-preview``) and ``browser-blank-screen-fix`` (preview/apply).
    Referenced from ``why-broken`` when IPv4 origin is OK but the UI still fails.

Key invariants:
    * Observation ≠ proof; blank UI can be GPU, cache, extension, or site JS.
    * Fix defaults to ``dry_run=True``; live apply needs
      ``CLEAR_EDGE_BLANK_SCREEN_CACHES``.
    * Does not re-enable Wi-Fi IPv6 or weaken proxy/DNS safety gates.
    * Stopping Edge is optional and only on confirmed live apply.

Side effects:
    Diagnose: filesystem reads under Edge User Data; optional URL probes.
    Fix apply: may stop ``msedge``, delete cache dirs, rewrite Preferences.

Audit Notes:
    Appends ``.audit/browser-blank-screen.jsonl``. Preserve ``limitations[]``.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, DEFAULT_SAFETY_NOTES, is_demo_mode

CONFIRMATION_PHRASE = CONFIRMATION_TOKENS.get(
    "CLEAR_EDGE_BLANK_SCREEN_CACHES", "CLEAR_EDGE_BLANK_SCREEN_CACHES"
)

DEFAULT_PROBE_URL = "https://www.linkedin.com/"

BLANK_SCREEN_LIMITATIONS = [
    "Blank/black UI with HTTP 200 on origin is correlation — not proof of a single root cause.",
    "GPU/cache cleanup does not fix ISP IPv6 blackholes; use ipv6-path for path issues.",
    "Extensions, corporate MDM, and site JS bugs can still blank the page after cleanup.",
    *DEFAULT_SAFETY_NOTES,
]


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def edge_user_data_dir() -> Path:
    """Return the current user's Edge ``User Data`` directory (may not exist)."""
    local = os.environ.get("LOCALAPPDATA") or ""
    return Path(local) / "Microsoft" / "Edge" / "User Data"


_edge_user_data_dir = edge_user_data_dir


def _cache_targets(user_data: Path) -> list[dict[str, Any]]:
    rels = [
        "Default/GPUCache",
        "Default/ShaderCache",
        "Default/Code Cache",
        "Default/Service Worker/CacheStorage",
        "GraphiteDawnCache",
        "GrShaderCache",
        "ShaderCache",
    ]
    rows: list[dict[str, Any]] = []
    for rel in rels:
        path = user_data / Path(rel)
        exists = path.is_dir()
        size = 0
        if exists:
            try:
                size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
            except OSError:
                size = -1
        rows.append(
            {
                "relative": rel.replace("\\", "/"),
                "path": str(path),
                "exists": exists,
                "bytes": size,
            }
        )
    return rows


def _read_local_state_hw_accel(local_state_path: Path) -> tuple[bool, bool | None]:
    """Return ``(readable, enabled)`` from Local State ``hardware_acceleration_mode.enabled``."""
    try:
        data = json.loads(local_state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, None
    node = data.get("hardware_acceleration_mode") if isinstance(data, dict) else None
    enabled = node.get("enabled") if isinstance(node, dict) else None
    return True, enabled if isinstance(enabled, bool) else None


def _read_hw_accel(prefs_path: Path, local_state_path: Path | None = None) -> dict[str, Any]:
    """Effective Edge hardware-acceleration setting.

    Edge reads ``hardware_acceleration_mode.enabled`` from ``Local State``; an absent key
    means the Chromium default (enabled). The profile ``Preferences`` key is legacy and
    ignored by Edge, so it is only used when Local State is unavailable.
    """
    legacy: bool | None = None
    error: str | None = None
    present = prefs_path.is_file()
    if not present:
        error = "prefs_missing"
    else:
        try:
            data = json.loads(prefs_path.read_text(encoding="utf-8"))
            legacy = data.get("hardware_acceleration_mode_enabled")
            if legacy is None and isinstance(data.get("browser"), dict):
                legacy = data["browser"].get("hardware_acceleration_mode_enabled")
        except (OSError, json.JSONDecodeError) as exc:
            error = str(exc)[:200]

    readable, local = (
        _read_local_state_hw_accel(local_state_path) if local_state_path else (False, None)
    )
    if local is not None:
        enabled, source = local, "local_state"
    elif readable:
        enabled, source = True, "chromium_default"
    else:
        enabled, source = legacy, "preferences_legacy"
    return {
        "prefs_path": str(prefs_path),
        "present": present,
        "hardware_acceleration_mode_enabled": enabled,
        "source": source,
        "preferences_legacy_value": legacy,
        "error": error,
    }


def _set_hw_accel(prefs_path: Path, *, enabled: bool) -> dict[str, Any]:
    if not prefs_path.is_file():
        return {"ok": False, "error": "prefs_missing"}
    try:
        data = json.loads(prefs_path.read_text(encoding="utf-8"))
        data["hardware_acceleration_mode_enabled"] = enabled
        if isinstance(data.get("browser"), dict):
            data["browser"]["hardware_acceleration_mode_enabled"] = enabled
        prefs_path.write_text(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )
        return {"ok": True, "hardware_acceleration_mode_enabled": enabled, "error": None}
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        return {"ok": False, "error": str(exc)[:200]}


def _edge_running() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        completed = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq msedge.exe"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return "msedge.exe" in (completed.stdout or "").lower()
    except (OSError, subprocess.SubprocessError):
        return False


def _stop_edge() -> dict[str, Any]:
    if platform.system() != "Windows":
        return {"ok": False, "error": "requires_windows"}
    try:
        completed = subprocess.run(
            ["taskkill", "/IM", "msedge.exe", "/F"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        return {
            "ok": completed.returncode in (0, 128),
            "returncode": completed.returncode,
            "excerpt": ((completed.stdout or "") + (completed.stderr or ""))[:240],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)[:200]}


def collect_edge_state(user_data_dir: Path | None = None) -> dict[str, Any]:
    """Read-only snapshot of Edge cache dirs, hardware acceleration, and process state.

    Args:
        user_data_dir: Override Edge User Data path (tests).

    Returns:
        Dict with ``user_data_dir``, ``running``, ``hardware_acceleration``,
        ``cache_targets``, ``cache_dirs_present``, and ``cache_bytes_total``.
    """
    user_data = user_data_dir or edge_user_data_dir()
    caches = _cache_targets(user_data)
    return {
        "user_data_dir": str(user_data),
        "running": _edge_running(),
        "hardware_acceleration": _read_hw_accel(
            user_data / "Default" / "Preferences", user_data / "Local State"
        ),
        "cache_targets": caches,
        "cache_dirs_present": sum(1 for c in caches if c.get("exists")),
        "cache_bytes_total": sum(max(int(c.get("bytes") or 0), 0) for c in caches),
    }


def probe_url_ipv4(
    url: str,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """HEAD-probe a URL over IPv4 (read-only)."""
    run_fn = run or subprocess.run
    host = urlparse(url).hostname or url
    if platform.system() != "Windows" and run is None:
        return {"url": url, "host": host, "ok": False, "error": "requires_windows"}
    try:
        completed = run_fn(
            ["curl.exe", "-4", "-I", "-sS", "--max-time", str(int(timeout)), url],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
        out = (completed.stdout or "") + (completed.stderr or "")
        ok = completed.returncode == 0 and ("HTTP/" in out or "HTTP/2" in out or "HTTP/3" in out)
        return {
            "url": url,
            "host": host,
            "ok": ok,
            "returncode": completed.returncode,
            "excerpt": out.strip()[:240] or None,
            "error": None if ok else f"curl_exit={completed.returncode}",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"url": url, "host": host, "ok": False, "error": str(exc)[:200]}


def classify_blank_screen(
    *,
    origin_ok: bool | None,
    ipv6_classification: str | None,
    prefer_ipv4: bool | None,
    hw_accel_enabled: bool | None,
    cache_dirs_present: int,
) -> dict[str, Any]:
    """Classify blank-screen evidence into a triage label.

    Decision intent:
        Prefer cache/GPU remediation when origin HTTPS works; escalate to
        ipv6-path when dual-stack blackhole is still primary.
    """
    if origin_ok is False:
        return {
            "primary_classification": "ORIGIN_UNREACHABLE",
            "severity": "medium",
            "confidence": 0.7,
            "reasoning": "Origin IPv4 probe failed — fix DNS/proxy/path before blank-screen cleanup.",
            "recommended_next_actions": [
                "python -m windows_network_toolkit why-broken --url <url>",
                "python -m windows_network_toolkit dns-edge-status",
            ],
        }

    if ipv6_classification == "IPV6_PATH_BLACKHOLE" and not prefer_ipv4:
        return {
            "primary_classification": "IPV6_BLACKHOLE_LIKELY",
            "severity": "medium",
            "confidence": 0.75,
            "reasoning": (
                "IPv6 path blackhole without prefer-IPv4 — dual-stack sites "
                "(LinkedIn/CDN) can blank or spin before GPU/cache is relevant."
            ),
            "recommended_next_actions": [
                "python -m windows_network_toolkit ipv6-prefer-ipv4 --dry-run true",
                "python -m windows_network_toolkit browser-blank-screen",
            ],
        }

    # Require positive evidence: existing cache dirs and/or HW accel explicitly on.
    # Unknown prefs (None) must not count as GPU evidence — that made
    # IPV6_MITIGATED / INCONCLUSIVE unreachable when caches were empty.
    if origin_ok and (cache_dirs_present > 0 or hw_accel_enabled is True):
        return {
            "primary_classification": "BROWSER_BLANK_SCREEN_CACHE_GPU",
            "severity": "medium",
            "confidence": 0.7,
            "reasoning": (
                "Origin IPv4 OK while UI is blank/black — typical Edge GPU/cache/"
                "service-worker corruption pattern (seen on LinkedIn/Upwork)."
            ),
            "recommended_next_actions": [
                "python -m windows_network_toolkit browser-blank-screen --with-fix-preview",
                "Live apply: python -m windows_network_toolkit browser-blank-screen-fix "
                f"--dry-run false --confirm {CONFIRMATION_PHRASE}",
                "Retest in Edge InPrivate after apply; reopen the affected site "
                "(e.g. https://www.linkedin.com/ or https://www.upwork.com/).",
            ],
        }

    if ipv6_classification == "IPV6_PATH_BLACKHOLE" and prefer_ipv4:
        return {
            "primary_classification": "IPV6_MITIGATED_TRY_BLANK_SCREEN_FIX",
            "severity": "low",
            "confidence": 0.6,
            "reasoning": (
                "Prefer-IPv4 already set but blank UI persists — try Edge cache/GPU "
                "cleanup; optional Wi-Fi IPv6 binding disable remains operator-owned."
            ),
            "recommended_next_actions": [
                "python -m windows_network_toolkit browser-blank-screen --with-fix-preview",
            ],
        }

    return {
        "primary_classification": "INCONCLUSIVE_CLIENT_OR_SITE",
        "severity": "info",
        "confidence": 0.45,
        "reasoning": "Insufficient blank-screen signals; try InPrivate / extensions / site JS.",
        "recommended_next_actions": [
            "Open site in Edge InPrivate",
            "python -m windows_network_toolkit why-broken --url <url>",
        ],
    }


def _attach_fix_preview(
    payload: dict[str, Any],
    *,
    user_data_dir: Path | None = None,
) -> dict[str, Any]:
    """Attach a dry-run remediation preview (never applies)."""
    preview = remediate_browser_blank_screen(dry_run=True, user_data_dir=user_data_dir)
    payload["fix_preview"] = preview
    payload["operator_next_step"] = {
        "kind": "apply_blank_screen_fix",
        "command": (
            "python -m windows_network_toolkit browser-blank-screen-fix "
            f"--dry-run false --confirm {CONFIRMATION_PHRASE}"
        ),
        "reason": (
            "Diagnose+preview complete. Reply with the exact token "
            f"{CONFIRMATION_PHRASE} to apply (closes Edge; clears GPU/code caches)."
        ),
        "confirmation_required": CONFIRMATION_PHRASE,
    }
    return payload


def diagnose_browser_blank_screen(
    *,
    url: str = DEFAULT_PROBE_URL,
    inject: dict[str, Any] | None = None,
    run: Callable[..., Any] | None = None,
    user_data_dir: Path | None = None,
    with_fix_preview: bool = False,
) -> dict[str, Any]:
    """Read-only blank-screen investigation.

    Args:
        url: Page that appears blank (default LinkedIn).
        inject: Fixture dict for deterministic tests.
        run: Optional subprocess runner for URL probes.
        user_data_dir: Override Edge User Data path (tests).
        with_fix_preview: When True, attach dry-run ``fix_preview`` in the same
            payload so operators/agents need only one diagnose round-trip before
            asking for the typed apply token.

    Returns:
        Governance-enveloped diagnose payload with classification and next step.
    """
    if inject is not None:
        payload = dict(inject)
        payload.setdefault("timestamp_utc", _utc_now())
        payload.setdefault("command", "browser-blank-screen")
        payload.setdefault("limitations", list(BLANK_SCREEN_LIMITATIONS))
        if with_fix_preview:
            payload = _attach_fix_preview(payload, user_data_dir=user_data_dir)
        return attach_governance_envelope(payload, dry_run=True)

    if platform.system() != "Windows" and user_data_dir is None and run is None:
        return attach_governance_envelope(
            {
                "timestamp_utc": _utc_now(),
                "command": "browser-blank-screen",
                "unsupported_platform": True,
                "platform": platform.system(),
                "message": "browser-blank-screen requires Windows (or --fixture).",
                "limitations": list(BLANK_SCREEN_LIMITATIONS),
            },
            dry_run=True,
        )

    user_data = user_data_dir or _edge_user_data_dir()
    edge_state = collect_edge_state(user_data)
    caches = edge_state["cache_targets"]
    hw = edge_state["hardware_acceleration"]
    origin = probe_url_ipv4(url, run=run)

    ipv6_cls = None
    prefer = None
    try:
        from windows_network_toolkit.ipv6_path import investigate_ipv6_path

        ipv6 = investigate_ipv6_path()
        path = ipv6.get("path") if isinstance(ipv6.get("path"), dict) else {}
        ipv6_cls = path.get("classification")
        prefer = path.get("prefer_ipv4_bit_set")
    except Exception as exc:  # noqa: BLE001 — diagnose soft-fail
        ipv6_cls = None
        prefer = None
        ipv6_error = str(exc)[:200]
    else:
        ipv6_error = None

    present = edge_state["cache_dirs_present"]
    classification = classify_blank_screen(
        origin_ok=origin.get("ok"),
        ipv6_classification=str(ipv6_cls) if ipv6_cls else None,
        prefer_ipv4=bool(prefer) if prefer is not None else None,
        hw_accel_enabled=hw.get("hardware_acceleration_mode_enabled"),
        cache_dirs_present=present,
    )

    next_cmds = classification.get("recommended_next_actions") or []
    next_step = {
        "kind": "browser_blank_screen",
        "command": next_cmds[0] if next_cmds else None,
        "reason": classification.get("reasoning"),
    }

    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "command": "browser-blank-screen",
        "url": url,
        "origin_probe": origin,
        "ipv6": {
            "classification": ipv6_cls,
            "prefer_ipv4_bit_set": prefer,
            "error": ipv6_error,
        },
        "edge": {
            "user_data_dir": edge_state["user_data_dir"],
            "running": edge_state["running"],
            "hardware_acceleration": hw,
            "cache_targets": caches,
            "cache_dirs_present": present,
        },
        "classification": classification.get("primary_classification"),
        "classification_result": classification,
        "operator_next_step": next_step,
        "limitations": list(BLANK_SCREEN_LIMITATIONS),
    }
    if with_fix_preview:
        payload = _attach_fix_preview(payload, user_data_dir=user_data)
    return attach_governance_envelope(payload, dry_run=True)


def remediate_browser_blank_screen(
    *,
    dry_run: bool = True,
    confirm: str = "",
    stop_edge: bool = True,
    clear_caches: bool = True,
    disable_hw_accel: bool = True,
    user_data_dir: Path | None = None,
    inject: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Preview or apply Edge blank-screen cache/GPU remediation.

    Args:
        dry_run: When True (default), plan only.
        confirm: Must equal ``CLEAR_EDGE_BLANK_SCREEN_CACHES`` for live apply.
        stop_edge: Stop msedge before deleting caches (recommended).
        clear_caches: Delete known GPU/code/service-worker cache dirs.
        disable_hw_accel: Set Edge prefs hardware acceleration off.
        user_data_dir: Override Edge User Data (tests).
        inject: Fixture override (tests).

    Returns:
        Remediation payload with ``action_allowed``, planned/applied actions,
        and audit soft-append status.
    """
    if inject is not None:
        payload = dict(inject)
        payload.setdefault("timestamp_utc", _utc_now())
        payload.setdefault("command", "browser-blank-screen-fix")
        payload.setdefault("dry_run", dry_run)
        return attach_governance_envelope(payload, dry_run=dry_run)

    if is_demo_mode():
        dry_run = True

    token_ok = (confirm or "") == CONFIRMATION_PHRASE
    action_allowed = (not dry_run) and token_ok and not is_demo_mode()

    user_data = user_data_dir or _edge_user_data_dir()
    prefs = user_data / "Default" / "Preferences"
    caches = _cache_targets(user_data)
    planned: list[dict[str, Any]] = []
    if stop_edge:
        planned.append({"id": "stop_msedge", "description": "Stop Microsoft Edge processes"})
    if clear_caches:
        for row in caches:
            if row.get("exists"):
                planned.append(
                    {
                        "id": "clear_cache_dir",
                        "path": row["path"],
                        "relative": row["relative"],
                    }
                )
    if disable_hw_accel:
        planned.append(
            {
                "id": "disable_hardware_acceleration",
                "prefs_path": str(prefs),
                "set": False,
            }
        )

    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "command": "browser-blank-screen-fix",
        "dry_run": dry_run,
        "confirmation_required": CONFIRMATION_PHRASE,
        "confirm_provided_ok": token_ok,
        "action_allowed": action_allowed,
        "edge_user_data": str(user_data),
        "planned_actions": planned,
        "applied_actions": [],
        "limitations": list(BLANK_SCREEN_LIMITATIONS),
    }

    if dry_run:
        payload["message"] = "Preview only — no Edge caches cleared."
        payload["operator_next_step"] = {
            "kind": "apply_blank_screen_fix",
            "command": (
                "python -m windows_network_toolkit browser-blank-screen-fix "
                f"--dry-run false --confirm {CONFIRMATION_PHRASE}"
            ),
            "reason": "Close important Edge tabs first; apply clears GPU/code caches and disables HW accel.",
        }
        payload = attach_governance_envelope(payload, dry_run=True)
        ok, err = append_audit_dict(
            {
                "event": "browser_blank_screen_fix",
                "dry_run": True,
                "action_allowed": False,
                "planned_count": len(planned),
            },
            log_name="browser-blank-screen.jsonl",
        )
        payload["audit_appended"] = ok
        payload["audit_error"] = err
        return payload

    if not token_ok:
        payload["message"] = f"Live apply blocked: confirm must be exactly {CONFIRMATION_PHRASE}."
        payload = attach_governance_envelope(payload, dry_run=False, policy_outcome="BLOCK")
        append_audit_dict(
            {
                "event": "browser_blank_screen_fix",
                "dry_run": False,
                "action_allowed": False,
                "reason": "bad_confirm",
            },
            log_name="browser-blank-screen.jsonl",
        )
        return payload

    applied: list[dict[str, Any]] = []
    if stop_edge:
        applied.append({"id": "stop_msedge", **_stop_edge()})
    if clear_caches:
        for row in caches:
            if not row.get("exists"):
                continue
            path = Path(row["path"])
            try:
                shutil.rmtree(path, ignore_errors=False)
                applied.append({"id": "clear_cache_dir", "path": str(path), "ok": True})
            except OSError as exc:
                applied.append(
                    {
                        "id": "clear_cache_dir",
                        "path": str(path),
                        "ok": False,
                        "error": str(exc)[:200],
                    }
                )
    if disable_hw_accel:
        applied.append(
            {"id": "disable_hardware_acceleration", **_set_hw_accel(prefs, enabled=False)}
        )

    payload["applied_actions"] = applied
    payload["message"] = (
        "Applied Edge blank-screen cleanup. Reopen Edge InPrivate and retest the site "
        "(e.g. https://www.linkedin.com/)."
    )
    payload["operator_next_step"] = {
        "kind": "retest",
        "command": "python -m windows_network_toolkit browser-blank-screen --url https://www.linkedin.com/",
        "reason": "Verify origin still OK and UI paints after cache/GPU cleanup.",
    }
    payload = attach_governance_envelope(payload, dry_run=False)
    ok, err = append_audit_dict(
        {
            "event": "browser_blank_screen_fix",
            "dry_run": False,
            "action_allowed": True,
            "applied_count": len(applied),
        },
        log_name="browser-blank-screen.jsonl",
    )
    payload["audit_appended"] = ok
    payload["audit_error"] = err
    return payload
