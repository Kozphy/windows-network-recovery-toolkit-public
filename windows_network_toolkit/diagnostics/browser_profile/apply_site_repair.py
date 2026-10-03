"""Site-scoped Chromium/Edge repair mutations (confirmation-gated callers only).

Module responsibility:
    Perform domain-guarded filesystem/SQLite cleanup for cookies, IndexedDB,
    Service Worker caches, and Preferences site exceptions. Does **not** disable
    extensions or wipe whole profiles.

System placement:
    Called only from ``runner.run_repair_apply`` after token verification.

Key invariants:
    * Every destructive path is scoped via ``domain_matches`` / origin-name tokens.
    * Shared Local Storage leveldb is never deleted wholesale.
    * Extension disable actions are explicitly skipped.
    * HTTP disk cache is opaque — reported as skipped, not wiped.

Side effects:
    May delete site-scoped dirs, DELETE cookie rows, rewrite Preferences JSON.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from windows_network_toolkit.diagnostics.browser_profile.adapters.chromium import (
    domain_matches,
)

# Actions that must never run automatically (safety + docs).
SKIP_ALWAYS = frozenset(
    {
        "create_clean_test_profile",
        "reset_secure_dns_to_system",
    }
)


def _host_tokens(domain: str) -> set[str]:
    d = domain.lower().lstrip(".")
    tokens = {d, d.replace(".", "_")}
    if d.startswith("www."):
        tokens.add(d[4:])
        tokens.add(d[4:].replace(".", "_"))
    else:
        tokens.add(f"www.{d}")
        tokens.add(f"www_{d}".replace(".", "_"))
    return tokens


def _origin_name_match(name: str, domain: str) -> bool:
    lowered = name.lower()
    return any(tok in lowered for tok in _host_tokens(domain))


def stop_browser_processes(process_names: tuple[str, ...]) -> dict[str, Any]:
    """Best-effort stop of browser processes (Windows taskkill)."""
    if not process_names:
        return {"ok": True, "skipped": True, "reason": "no_process_names"}
    results: list[dict[str, Any]] = []
    for name in process_names:
        try:
            completed = subprocess.run(
                ["taskkill", "/F", "/IM", name],
                capture_output=True,
                text=True,
                errors="ignore",
                check=False,
            )
            results.append(
                {
                    "process": name,
                    "returncode": completed.returncode,
                    "excerpt": (completed.stdout or completed.stderr or "")[:240],
                }
            )
        except OSError as exc:
            results.append({"process": name, "ok": False, "error": str(exc)[:200]})
    return {"ok": True, "results": results}


def delete_domain_cookies(cookies_db: Path, domain: str) -> dict[str, Any]:
    """DELETE cookie rows whose host_key matches ``domain`` (values never logged)."""
    if not cookies_db.is_file():
        return {
            "id": "delete_domain_cookies",
            "ok": True,
            "deleted": 0,
            "reason": "cookies_db_missing",
        }
    try:
        con = sqlite3.connect(str(cookies_db))
        cur = con.cursor()
        rows = cur.execute("SELECT rowid, host_key FROM cookies").fetchall()
        rowids = [int(rowid) for rowid, host_key in rows if domain_matches(domain, str(host_key))]
        if rowids:
            cur.executemany("DELETE FROM cookies WHERE rowid = ?", [(rid,) for rid in rowids])
        con.commit()
        con.close()
        return {"id": "delete_domain_cookies", "ok": True, "deleted": len(rowids)}
    except sqlite3.Error as exc:
        return {"id": "delete_domain_cookies", "ok": False, "error": str(exc)[:200]}


def delete_matching_origin_dirs(root: Path, domain: str, *, action_id: str) -> dict[str, Any]:
    """Remove immediate child dirs under ``root`` whose names embed the domain."""
    if not root.is_dir():
        return {"id": action_id, "ok": True, "removed": 0, "reason": "dir_missing"}
    removed: list[str] = []
    errors: list[str] = []
    try:
        children = list(root.iterdir())
    except OSError as exc:
        return {"id": action_id, "ok": False, "error": str(exc)[:200]}
    for child in children:
        if not child.is_dir():
            continue
        if not _origin_name_match(child.name, domain):
            continue
        try:
            shutil.rmtree(child)
            removed.append(child.name)
        except OSError as exc:
            errors.append(f"{child.name}:{exc}"[:200])
    return {
        "id": action_id,
        "ok": not errors,
        "removed": len(removed),
        "removed_names": removed[:20],
        "errors": errors or None,
    }


def reset_domain_permissions(prefs_path: Path, domain: str) -> dict[str, Any]:
    """Remove Preferences content_settings exceptions matching the domain."""
    if not prefs_path.is_file():
        return {
            "id": "reset_domain_permissions",
            "ok": True,
            "removed_keys": 0,
            "reason": "prefs_missing",
        }
    try:
        data = json.loads(prefs_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"id": "reset_domain_permissions", "ok": False, "error": str(exc)[:200]}

    removed = 0
    pattern = re.compile(re.escape(domain.lower().lstrip(".")), re.I)

    def _prune(obj: Any) -> Any:
        nonlocal removed
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and pattern.search(k):
                    removed += 1
                    continue
                out[k] = _prune(v)
            return out
        if isinstance(obj, list):
            return [_prune(x) for x in obj]
        return obj

    profile = data.get("profile")
    if isinstance(profile, dict):
        cs = profile.get("content_settings")
        if isinstance(cs, dict):
            profile["content_settings"] = _prune(cs)
            data["profile"] = profile

    try:
        prefs_path.write_text(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )
    except OSError as exc:
        return {"id": "reset_domain_permissions", "ok": False, "error": str(exc)[:200]}
    return {"id": "reset_domain_permissions", "ok": True, "removed_keys": removed}


def apply_site_actions(
    *,
    profile_path: Path,
    domain: str,
    actions: list[dict[str, Any]],
    process_names: tuple[str, ...] = (),
    stop_browser: bool = True,
) -> dict[str, Any]:
    """Apply allowlisted site-scoped actions under ``profile_path``.

    Args:
        profile_path: Chromium profile directory (e.g. ``.../User Data/Default``).
        domain: Diagnosed domain (guard key).
        actions: Preview action dicts (``id``, …).
        process_names: Browser processes to stop before SQLite writes.
        stop_browser: When True, attempt taskkill first.

    Returns:
        Result payload with ``applied`` / ``skipped`` lists and ``mutated`` bool.
    """
    d = domain.lower().lstrip(".")
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    stop_info = None
    if stop_browser and process_names:
        stop_info = stop_browser_processes(process_names)
        applied.append({"id": "stop_browser", **stop_info})

    cookies_db = profile_path / "Network" / "Cookies"
    if not cookies_db.is_file():
        cookies_db = profile_path / "Cookies"

    for action in actions:
        aid = str(action.get("id") or "")
        if aid.startswith("disable_extension_"):
            skipped.append(
                {
                    "id": aid,
                    "reason": "never_auto_disable_extensions",
                }
            )
            continue
        if aid in SKIP_ALWAYS:
            skipped.append({"id": aid, "reason": "deferred_non_site_scoped"})
            continue
        if aid == "delete_domain_cache":
            skipped.append(
                {
                    "id": aid,
                    "reason": "http_disk_cache_opaque_not_domain_attributed",
                }
            )
            continue
        if aid == "delete_domain_cookies":
            applied.append(delete_domain_cookies(cookies_db, d))
            continue
        if aid == "delete_domain_local_storage":
            # Shared Local Storage/leveldb is not wiped; IndexedDB origin dirs only.
            idb = delete_matching_origin_dirs(
                profile_path / "IndexedDB", d, action_id="delete_domain_indexeddb"
            )
            applied.append(idb)
            skipped.append(
                {
                    "id": "delete_domain_local_storage_leveldb",
                    "reason": "shared_leveldb_not_wiped_use_browser_ui_if_needed",
                }
            )
            continue
        if aid == "unregister_domain_service_workers":
            for rel, label in (
                ("Service Worker/CacheStorage", "sw_cache_storage"),
                ("Service Worker/ScriptCache", "sw_script_cache"),
                ("Service Worker/Database", "sw_database"),
            ):
                applied.append(
                    delete_matching_origin_dirs(
                        profile_path / Path(rel),
                        d,
                        action_id=f"unregister_domain_service_workers:{label}",
                    )
                )
            continue
        if aid == "reset_domain_permissions":
            applied.append(reset_domain_permissions(profile_path / "Preferences", d))
            continue
        skipped.append({"id": aid, "reason": "unknown_action"})

    mutated = any(
        row.get("ok")
        and (
            int(row.get("deleted") or 0) > 0
            or int(row.get("removed") or 0) > 0
            or int(row.get("removed_keys") or 0) > 0
        )
        for row in applied
        if row.get("id") != "stop_browser"
    )

    return {
        "domain": d,
        "profile_path": str(profile_path),
        "applied": applied,
        "skipped": skipped,
        "mutated": mutated,
    }
