"""Shared Chromium (Edge/Chrome) profile inspectors — copy SQLite; never write live DBs.

Module responsibility:
    Read Chromium profile metadata (cookies meta, extensions, policies, site state)
    via temporary DB copies.

System placement:
    Used by Chrome/Edge adapters and browser-profile runners.

Key invariants:
    Never write live browser databases. Cookie *values* are not persisted.
    Soft-fail when files are locked or missing.

Side effects:
    Temporary file copies under system temp; optional process existence checks.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from windows_network_toolkit.diagnostics.browser_profile.models import (
    BrowserCookieMeta,
    BrowserExtensionEvidence,
    BrowserNetworkPreferenceEvidence,
    BrowserPolicyEvidence,
    BrowserProfileEvidence,
    BrowserSiteStateEvidence,
    EvidenceMeta,
    ReliabilityTier,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _meta(
    source: str, method: str, tier: ReliabilityTier = ReliabilityTier.T1_STATIC_CONFIG, **kw: Any
) -> EvidenceMeta:
    return EvidenceMeta(
        source=source,
        collected_at_utc=_now(),
        collection_method=method,
        reliability_tier=tier,
        **kw,
    )


def domain_matches(host: str, cookie_domain: str) -> bool:
    """Return True if ``cookie_domain`` applies to ``host`` via suffix matching.

    Used as a domain guard to ensure repair actions and cookie reads are scoped
    to the intended domain and never affect unrelated domains.

    Args:
        host: The bare hostname to test (e.g. ``"app.example.com"``).
        cookie_domain: The cookie's domain attribute (e.g. ``".example.com"``).
            Leading dots are stripped before comparison.

    Returns:
        ``True`` if ``host`` equals ``cookie_domain`` or is a subdomain of it.
    """
    h = host.lower().lstrip(".")
    d = cookie_domain.lower().lstrip(".")
    return h == d or h.endswith("." + d)


def _copy_sqlite(src: Path) -> Path | None:
    if not src.is_file():
        return None
    td = Path(tempfile.mkdtemp(prefix="wnt_browser_"))
    dst = td / src.name
    try:
        shutil.copy2(src, dst)
        # Chromium WAL companions
        for suffix in ("-wal", "-shm"):
            side = Path(str(src) + suffix)
            if side.is_file():
                shutil.copy2(side, Path(str(dst) + suffix))
        return dst
    except OSError:
        shutil.rmtree(td, ignore_errors=True)
        return None


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def is_browser_process_running(process_names: tuple[str, ...]) -> bool:
    """Check whether any of the given browser process names is currently running.

    Falls back to ``tasklist`` on Windows when ``psutil`` is not installed.

    Args:
        process_names: Tuple of process name strings to check (e.g.
            ``("msedge.exe", "msedgewebview2.exe")``).

    Returns:
        ``True`` if at least one matching process is detected; ``False`` otherwise
        or on any enumeration error.
    """
    try:
        import psutil  # type: ignore
    except ImportError:
        # Fallback: tasklist on Windows
        try:
            import subprocess

            out = subprocess.check_output(["tasklist"], text=True, errors="ignore")
            lower = out.lower()
            return any(n.lower() in lower for n in process_names)
        except (OSError, subprocess.SubprocessError):
            return False
    names = {n.lower() for n in process_names}
    for p in psutil.process_iter(["name"]):
        try:
            if (p.info.get("name") or "").lower() in names:
                return True
        except (psutil.Error, TypeError):
            continue
    return False


class ChromiumProfileMixin:
    """Helpers shared by Edge and Chrome adapters."""

    browser_name: str = "chromium"
    process_names: tuple[str, ...] = ()
    user_data_candidates: tuple[Path, ...] = ()

    def detect_installation(self) -> dict[str, Any]:
        """Return whether the browser profile root is available.

        Args:
            None.

        Returns:
            Dict with ``installed`` status, browser name, and optional user data directory.

        Side effects:
            Reads filesystem metadata for candidate profile directories."""
        for p in self.user_data_candidates:
            # installation detected if user data exists
            if p.is_dir():
                return {"installed": True, "user_data_dir": str(p), "browser": self.browser_name}
        return {"installed": False, "browser": self.browser_name}

    def _user_data_dir(self) -> Path | None:
        for p in self.user_data_candidates:
            if p.is_dir():
                return p
        return None

    def discover_profiles(self) -> list[BrowserProfileEvidence]:
        """Discover browser profiles under the configured User Data root.

        Args:
            None.

        Returns:
            List of ``BrowserProfileEvidence`` objects for discovered profiles.

        Side effects:
            Reads profile directory metadata and may enumerate browser processes."""
        root = self._user_data_dir()
        if root is None:
            return []
        open_flag = is_browser_process_running(self.process_names)
        profiles: list[BrowserProfileEvidence] = []
        # Local State maps profile directories
        local_state = _read_json(root / "Local State")
        info_cache = (local_state.get("profile") or {}).get("info_cache") or {}
        dirs = ["Default"] + [
            d.name for d in root.iterdir() if d.is_dir() and d.name.startswith("Profile ")
        ]
        seen: set[str] = set()
        for dirname in dirs:
            path = root / dirname
            if not path.is_dir() or dirname in seen:
                continue
            seen.add(dirname)
            cache = info_cache.get(dirname) or {}
            profiles.append(
                BrowserProfileEvidence(
                    browser=self.browser_name,
                    profile_id=dirname,
                    profile_name=str(cache.get("name") or dirname),
                    profile_path=str(path),
                    is_default=dirname == "Default",
                    browser_open=open_flag,
                    meta=_meta(self.browser_name, "discover_profiles"),
                )
            )
        return profiles

    def collect_profile_metadata(self, profile: BrowserProfileEvidence) -> BrowserProfileEvidence:
        """Refresh metadata for a discovered browser profile.

        Args:
            profile: Profile evidence object to enrich.

        Returns:
            Updated ``BrowserProfileEvidence`` with profile name/open-state metadata.

        Side effects:
            Reads profile preference files and may enumerate browser processes."""
        path = Path(profile.profile_path)
        version = ""
        prefs = _read_json(path / "Preferences")
        version = str((prefs.get("profile") or {}).get("name") or profile.profile_name)
        return profile.model_copy(
            update={
                "browser_version": profile.browser_version or "",
                "profile_name": version or profile.profile_name,
                "browser_open": is_browser_process_running(self.process_names),
                "meta": _meta(self.browser_name, "collect_profile_metadata"),
            }
        )

    def collect_network_preferences(
        self, profile: BrowserProfileEvidence
    ) -> BrowserNetworkPreferenceEvidence:
        """Collect browser network preference metadata for one profile.

        Args:
            profile: Profile whose network preferences should be inspected.

        Returns:
            ``BrowserNetworkPreferenceEvidence`` with DNS-over-HTTPS and proxy settings.

        Side effects:
            Reads the profile ``Preferences`` JSON file only."""
        prefs = _read_json(Path(profile.profile_path) / "Preferences")
        dns = prefs.get("dns_over_https") or prefs.get("dns_over_https.mode") or {}
        if isinstance(dns, str):
            mode = dns
            templates: list[str] = []
        else:
            mode = str(dns.get("mode") or "")
            templates = (
                list(dns.get("templates") or []) if isinstance(dns.get("templates"), list) else []
            )
        proxy = prefs.get("proxy") or {}
        return BrowserNetworkPreferenceEvidence(
            secure_dns_mode=mode or None,
            secure_dns_templates=[str(t) for t in templates],
            proxy_mode=str(proxy.get("mode") or "") or None,
            proxy_server=str(proxy.get("server") or "") or None,
            pac_url=str(proxy.get("pac_url") or proxy.get("pacURL") or "") or None,
            meta=_meta(self.browser_name, "preferences_json"),
        )

    def collect_extension_metadata(
        self, profile: BrowserProfileEvidence
    ) -> list[BrowserExtensionEvidence]:
        """Collect extension metadata for one browser profile.

        Args:
            profile: Profile whose extension settings should be inspected.

        Returns:
            List of ``BrowserExtensionEvidence`` objects.

        Side effects:
            Reads the profile ``Preferences`` JSON file only."""
        prefs = _read_json(Path(profile.profile_path) / "Preferences")
        settings = (prefs.get("extensions") or {}).get("settings") or {}
        out: list[BrowserExtensionEvidence] = []
        for ext_id, cfg in settings.items():
            if not isinstance(cfg, dict):
                continue
            manifest = cfg.get("manifest") or {}
            name = str(manifest.get("name") or cfg.get("path") or ext_id)
            perms = list(manifest.get("permissions") or []) + list(
                manifest.get("host_permissions") or []
            )
            update_url = str(cfg.get("update_url") or manifest.get("update_url") or "") or None
            state = cfg.get("state")
            enabled = (
                True
                if state in (None, 1, "1")
                else bool(state)
                if isinstance(state, bool)
                else state != 0
            )
            looks = any(
                x in " ".join(str(p).lower() for p in perms) or x in name.lower()
                for x in ("proxy", "webRequest", "declarativeNetRequest")
            )
            out.append(
                BrowserExtensionEvidence(
                    extension_id=str(ext_id),
                    name=name,
                    enabled=enabled,
                    permissions=[str(p) for p in perms[:40]],
                    update_url=update_url,
                    looks_like_proxy=looks or "proxy" in name.lower(),
                    meta=_meta(self.browser_name, "extensions.settings"),
                )
            )
        return out

    def collect_policy_metadata(self) -> list[BrowserPolicyEvidence]:
        # Windows registry policies under HKLM/HKCU — best-effort, no admin required for HKCU
        """Collect browser policy metadata relevant to diagnostics.

        Args:
            None.

        Returns:
            List of ``BrowserPolicyEvidence`` objects.

        Side effects:
            Reads managed policy files and environment hints; does not modify browser state."""
        keys = [
            ("ProxySettings", ["proxy"]),
            ("DnsOverHttpsMode", ["dns", "doh"]),
            ("ExtensionInstallBlocklist", ["extensions"]),
            ("CookiesAllowedForUrls", ["cookies"]),
            ("DefaultCookiesSetting", ["cookies"]),
            ("JavaScriptEnabled", ["javascript"]),
            ("SSLVersionMin", ["tls"]),
        ]
        out: list[BrowserPolicyEvidence] = []
        # Prefer reading Local State / Policy JSON if present
        root = self._user_data_dir()
        if root:
            policy_file = root / "Policy" / "chrome.json"
            if not policy_file.is_file():
                policy_file = root / "Managed Preferences"
            # Edge uses different managed paths; also try Preferences for managed flags
            data = _read_json(policy_file) if policy_file.is_file() else {}
            for k, tags in keys:
                if k in data:
                    out.append(
                        BrowserPolicyEvidence(
                            key=k,
                            value_summary=str(data[k])[:200],
                            relevant_to=tags,
                            meta=_meta(self.browser_name, "managed_policy_file"),
                        )
                    )
        # Env hint for enterprise
        if os.environ.get("CHROME_HEADLESS") or os.environ.get("EDGE_HEADLESS"):
            out.append(
                BrowserPolicyEvidence(
                    key="env_headless_hint",
                    value_summary="headless env present",
                    relevant_to=["automation"],
                    meta=_meta(self.browser_name, "env"),
                )
            )
        return out

    def collect_site_state_metadata(
        self, domain: str, profile: BrowserProfileEvidence
    ) -> BrowserSiteStateEvidence:
        """Collect redacted site-state metadata for one domain/profile pair.

        Args:
            domain: Domain to match against cookies and storage paths.
            profile: Profile whose site state should be inspected.

        Returns:
            ``BrowserSiteStateEvidence`` with counts and redacted metadata.

        Side effects:
            Reads profile files and temporary SQLite copies; never writes live browser databases."""
        path = Path(profile.profile_path)
        open_flag = is_browser_process_running(self.process_names)
        cookies_meta: list[BrowserCookieMeta] = []
        cookie_count = 0
        error: str | None = None
        cookies_db = path / "Network" / "Cookies"
        if not cookies_db.is_file():
            cookies_db = path / "Cookies"
        copied = _copy_sqlite(cookies_db) if cookies_db.is_file() else None
        if copied is not None:
            try:
                con = sqlite3.connect(str(copied))
                cur = con.cursor()
                # Chromium cookies schema: host_key, name, path, is_secure, is_httponly, samesite, expires_utc
                rows = cur.execute(
                    "SELECT host_key, path, is_secure, is_httponly, samesite, expires_utc FROM cookies"
                ).fetchall()
                con.close()
                for host_key, cpath, secure, httponly, samesite, _expires in rows:
                    if not domain_matches(domain, str(host_key)):
                        continue
                    cookie_count += 1
                    cookies_meta.append(
                        BrowserCookieMeta(
                            domain=str(host_key),
                            path=str(cpath or "/"),
                            secure=bool(secure),
                            http_only=bool(httponly),
                            same_site=str(samesite) if samesite is not None else None,
                            expired=None,
                        )
                    )
            except sqlite3.Error as exc:
                error = f"cookies_sqlite:{exc}"
            finally:
                shutil.rmtree(copied.parent, ignore_errors=True)
        elif cookies_db.is_file():
            error = "cookies_copy_failed"
        elif open_flag:
            error = "browser_open_may_lock_sqlite"

        sw_count = 0
        # Count is approximate from directory listing when DB opaque
        sw_dir = path / "Service Worker" / "ScriptCache"
        if sw_dir.is_dir():
            try:
                # Heuristic: registration dirs mentioning domain
                for child in sw_dir.rglob("*"):
                    if domain.replace(".", "_") in child.name or domain in child.name:
                        sw_count += 1
            except OSError:
                pass

        # Disk HTTP cache is opaque; do not attribute whole Cache_Data size to one domain.
        cache_present = False
        cache_bytes = None

        # Chromium Local Storage / IndexedDB folder names embed origin hosts.
        host_tokens = {domain.lower().lstrip(".")}
        if domain.lower().startswith("www."):
            host_tokens.add(domain.lower()[4:])
        else:
            host_tokens.add(f"www.{domain.lower()}")

        def _origin_dir_match(name: str) -> bool:
            lowered = name.lower()
            return any(tok in lowered for tok in host_tokens)

        ls_present = False
        ls_root = path / "Local Storage" / "leveldb"
        if ls_root.is_dir():
            try:
                ls_present = any(_origin_dir_match(p.name) for p in ls_root.iterdir())
            except OSError:
                ls_present = False

        idb_present = False
        idb_root = path / "IndexedDB"
        if idb_root.is_dir():
            try:
                idb_present = any(_origin_dir_match(p.name) for p in idb_root.iterdir())
            except OSError:
                idb_present = False

        limitations = [
            "Cookie values were not read, decrypted, or logged.",
            "Chromium HTTP disk cache is not attributed to a single domain in this release.",
        ]

        return BrowserSiteStateEvidence(
            domain=domain,
            cookie_count=cookie_count,
            cookies_meta=cookies_meta[:50],
            service_worker_count=sw_count,
            cache_present=cache_present,
            cache_approx_bytes=cache_bytes,
            local_storage_present=ls_present,
            indexed_db_present=idb_present,
            meta=_meta(
                self.browser_name,
                "sqlite_copy_inspect",
                ReliabilityTier.T2_RUNTIME_CORROBORATION,
                error=error,
                redaction_status="fully_redacted",
            ),
            limitations=limitations,
        )
