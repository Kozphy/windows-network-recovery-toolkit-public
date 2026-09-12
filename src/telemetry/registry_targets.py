"""Canonical WinINET proxy registry targets and HKCU/HKU path normalization."""

from __future__ import annotations

INTERNET_SETTINGS_SUFFIX = r"software\microsoft\windows\currentversion\internet settings"

PROXY_VALUE_NAMES = frozenset(
    {
        "proxyenable",
        "proxyserver",
        "autoconfigurl",
        "proxyoverride",
    },
)

_HKCU_PREFIXES = (
    "hkcu\\",
    "hkey_current_user\\",
    "hkey_current_user/",
)


def normalize_registry_path(target_object: str, *, user_sid: str | None = None) -> str:
    """Normalize registry path for comparison.

    - Lowercase
    - Backslashes
    - HKCU / HKEY_CURRENT_USER -> HKU\\<SID> when *user_sid* provided, else HKU\\<current_user>
    """
    if not target_object:
        return ""
    text = target_object.strip().replace("/", "\\")
    low = text.lower()
    for prefix in _HKCU_PREFIXES:
        if low.startswith(prefix):
            sid = user_sid or "<current_user>"
            rest = text[len(prefix) :].lstrip("\\/")
            text = f"HKU\\{sid}\\{rest}"
            low = text.lower()
            break
    # Sysmon often logs HKU\S-1-5-21-...\Software\...
    low = low.replace("hkey_users\\", "hku\\")
    return low


def _canonical_suffix(low_path: str) -> str | None:
    """Return value name if path ends with Internet Settings\\<value>."""
    norm = low_path.replace("/", "\\")
    if INTERNET_SETTINGS_SUFFIX not in norm:
        return None
    tail = norm.split(INTERNET_SETTINGS_SUFFIX, 1)[-1].strip("\\")
    if not tail:
        return None
    atom = tail.split("\\")[-1].strip().rstrip(":")
    if atom in PROXY_VALUE_NAMES:
        return atom
    return None


def is_proxy_registry_target(target_object: str, *, user_sid: str | None = None) -> bool:
    """True when *target_object* is a monitored WinINET proxy value under Internet Settings."""
    if not target_object:
        return False
    low = normalize_registry_path(target_object, user_sid=user_sid)
    if _canonical_suffix(low):
        return True
    # Substring fallback for abbreviated exporter paths
    low_flat = low.replace("\\", "")
    if "internetsettings" in low_flat:
        for name in PROXY_VALUE_NAMES:
            if name in low_flat:
                return True
    return False


def proxy_registry_value_name(target_object: str, *, user_sid: str | None = None) -> str | None:
    """Return canonical value name (e.g. ``proxyenable``) or None."""
    if not target_object:
        return None
    low = normalize_registry_path(target_object, user_sid=user_sid)
    name = _canonical_suffix(low)
    if name:
        return name
    low_flat = low.replace("\\", "")
    for pv in PROXY_VALUE_NAMES:
        if pv in low_flat:
            return pv
    return None


def details_matches_expected(value_name: str, details: str, expected: object | None) -> bool:
    """Score whether Sysmon Details field matches the new proxy state."""
    d = (details or "").strip().lower()
    if value_name == "proxyserver" and expected is None:
        return d in ("", "(empty)", "null") or "deleted" in d
    if expected is None:
        return False
    if not d:
        return False
    if value_name == "proxyenable":
        if isinstance(expected, bool):
            exp = "1" if expected else "0"
        else:
            exp = str(expected).strip()
        if exp in ("1", "true"):
            return "00000001" in d or d in ("1", "0x1", "true", "dword (0x00000001)")
        if exp in ("0", "false"):
            return "00000000" in d or d in ("0", "0x0", "false", "dword (0x00000000)")
        return exp in d
    if value_name == "proxyserver":
        if expected is None:
            return d in ("", "(empty)", "null") or "deleted" in d
        exp_s = str(expected).strip().lower()
        if not exp_s or exp_s in ("none", "null"):
            return d in ("", "(empty)", "null") or "deleted" in d
        return exp_s in d.replace(" ", "")
    if value_name in ("autoconfigurl", "proxyoverride"):
        exp_s = str(expected).strip().lower()
        if not exp_s:
            return d in ("", "(empty)")
        return exp_s in d.lower()
    return str(expected).lower() in d
