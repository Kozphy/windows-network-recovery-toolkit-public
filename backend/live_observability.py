"""Optional FastAPI routes that delegate to ``python -m src`` subprocesses.

System position:
    Same repo checkout root as ``backend/`` siblings; relies on PYTHONPATH/importability of
    ``src`` when spawned via ``sys.executable``.

Key invariants:
    Authentication reuses ``get_current_user``; routes never bypass typed confirmation strings
    required by the CLI for destructive edits.

Audit Notes:
    ``/api/proxy/disable`` feeds the confirmation phrase through subprocess stdin; monitor
    ``logs/repair_audit.jsonl`` on the host running the FastAPI process.

Engineering Notes:
    Subprocess bridging keeps ``src/`` stdlib-only while reusing identical operator semantics
    as the terminal CLI.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .jwt_auth import AuthUser, get_current_user

_ROOT = Path(__file__).resolve().parent.parent


def _invoke_src_json(argv: list[str]) -> dict[str, Any]:
    """Run ``python -m src`` with fixed argv and parse stdout as JSON.

    Args:
        argv: Tokens after ``python -m src`` (subcommand and flags); must not include shell metacharacters—callers pass lists only.

    Returns:
        Parsed JSON object; empty dict when stdout is blank.

    Raises:
        HTTPException: When the subprocess exits non-zero or stdout is not valid JSON.

    Safety constraints:
        No shell invocation—argument vector only. Delegates policy inside ``src`` CLI (typed confirmations,
        dry-run, blocked high-risk actions). Review ``logs/repair_audit.jsonl`` on the API host when routes touch remediation.

    Side effects:
        Spawns a subprocess with repo root as cwd; bounded by ``timeout`` (300s).
    """
    proc = subprocess.run(
        [sys.executable, "-m", "src", *argv],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={"stderr": proc.stderr, "stdout": proc.stdout},
        )
    blob = proc.stdout.strip()
    if not blob:
        return {}
    try:
        return json.loads(blob)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502, detail={"parse_error": str(exc), "stdout": blob}
        ) from exc


def _invoke_src_json_status(argv: list[str], *, allowed_returncodes: set[int]) -> dict[str, Any]:
    """Run ``python -m src`` and parse JSON even when policy returns a non-zero block code."""

    proc = subprocess.run(
        [sys.executable, "-m", "src", *argv],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    blob = proc.stdout.strip()
    if proc.returncode not in allowed_returncodes:
        raise HTTPException(
            status_code=500,
            detail={"stderr": proc.stderr, "stdout": proc.stdout, "returncode": proc.returncode},
        )
    try:
        payload = json.loads(blob) if blob else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502, detail={"parse_error": str(exc), "stdout": blob}
        ) from exc
    if isinstance(payload, dict):
        payload.setdefault("returncode", proc.returncode)
        return payload
    raise HTTPException(
        status_code=502, detail={"parse_error": "stdout JSON was not an object", "stdout": blob}
    )


def _invoke_src_text(argv: list[str]) -> str:
    """Run ``python -m src`` and return raw stdout text (non-JSON commands).

    Args:
        argv: Tokens after ``python -m src``; list form only (no shell).

    Returns:
        Stripped stdout text on success.

    Raises:
        HTTPException: When the subprocess exits non-zero.

    Safety constraints:
        Same as :func:`_invoke_src_json` regarding subprocess and delegated CLI safety.

    Side effects:
        Subprocess with 300s timeout, cwd at repo root.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "src", *argv],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail={"stderr": proc.stderr, "stdout": proc.stdout})
    return proc.stdout.strip()


router = APIRouter(tags=["Toolkit observability"])


@router.get("/api/proxy/status")
def api_proxy_status(_user: AuthUser = Depends(get_current_user)) -> dict[str, Any]:
    """Expose merged HKCU proxy + parsed mapping as JSON."""
    return _invoke_src_json(["proxy-status", "--json"])


@router.get("/api/proxy/owner")
def api_proxy_owner(
    port: int | None = None,
    _user: AuthUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Resolve listener attribution for optional explicit ``port`` query param."""
    cmd = ["proxy-owner", "--json"]
    if port is not None:
        cmd.extend(["--port", str(port)])
    return _invoke_src_json(cmd)


@router.get("/api/proxy/events")
def api_proxy_events(
    tail: int = Query(10, ge=1, le=500),
    _user: AuthUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Return last ``tail`` JSONL rows from disk (best-effort parse)."""
    path = _ROOT / "logs" / "proxy_guard_events.jsonl"
    if not path.is_file():
        return {"tail": [], "path": str(path)}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-tail:]
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"unparsed": line})
    return {"path": str(path), "tail": events}


class DisablePreview(BaseModel):
    """Represent disable preview data used by the toolkit.
    
    Attributes:
        clear_server: Field or variant describing clear server evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    clear_server: bool = False


@router.post("/api/proxy/disable-preview")
def api_proxy_disable_preview(
    body: DisablePreview,
    _user: AuthUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Surface read-only preview produced by CLI ``proxy-disable --dry-run``."""
    payload = _invoke_src_json(
        ["proxy-disable", "--json", "--dry-run", "true"]
        + (["--clear-server"] if body.clear_server else []),
    )
    return {"preview_text": json.dumps(payload, indent=2, ensure_ascii=False), **payload}


class DisableConfirm(BaseModel):
    """Represent disable confirm data used by the toolkit.
    
    Attributes:
        dry_run: Field or variant describing dry run evidence or state.
        confirmation: Field or variant describing confirmation evidence or state.
        confirm: Field or variant describing confirm evidence or state.
        confirmation_text: Field or variant describing confirmation text evidence or state.
        clear_server: Field or variant describing clear server evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    dry_run: bool = True
    confirmation: str = ""
    confirm: bool | None = Field(
        default=None, description="Legacy field; ignored unless confirmation_text is used."
    )
    confirmation_text: str = ""
    clear_server: bool = False


DISABLE_PROXY_PHRASE = "DISABLE_WININET_PROXY"


@router.post("/api/proxy/disable")
def api_proxy_disable(
    body: DisableConfirm,
    _user: AuthUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Preview or apply HKCU proxy disable through the CLI confirmation gate."""
    confirmation = body.confirmation or body.confirmation_text or ""
    argv = [
        "proxy-disable",
        "--json",
        "--dry-run",
        "true" if body.dry_run else "false",
    ]
    if confirmation:
        argv.extend(["--confirm", confirmation])
    if body.clear_server:
        argv.append("--clear-server")
    return _invoke_src_json_status(argv, allowed_returncodes={0, 1})


@router.get("/api/snapshot")
def api_snapshot(_user: AuthUser = Depends(get_current_user)) -> dict[str, str]:
    """Trigger ``snapshot`` CLI; stdout contains human ``Wrote`` path marker."""
    return {"output": _invoke_src_text(["snapshot"])}


@router.post("/api/diagnose-live")
def api_diagnose_live(_user: AuthUser = Depends(get_current_user)) -> dict[str, Any]:
    """Return JSON-only diagnose-live payload (suppresses human banner)."""
    return _invoke_src_json(["diagnose-live", "--json"])


@router.get("/api/reports/latest")
def api_reports_latest_live(_user: AuthUser = Depends(get_current_user)) -> dict[str, Any]:
    """Serve ``last_diagnosis_live.json`` first, falling back to v1 artefact."""
    path = _ROOT / "reports" / "last_diagnosis_live.json"
    legacy = _ROOT / "reports" / "last_diagnosis.json"
    pick = path if path.is_file() else legacy
    if not pick.is_file():
        raise HTTPException(status_code=404, detail="No latest diagnosis artifact found.")
    return json.loads(pick.read_text(encoding="utf-8"))


class RestoreLkgRequest(BaseModel):
    """Represent restore lkg request data used by the toolkit.
    
    Attributes:
        dry_run: Field or variant describing dry run evidence or state.
        confirmation: Field or variant describing confirmation evidence or state.
        snapshot_name: Field or variant describing snapshot name evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    dry_run: bool = True
    confirmation: str = ""
    snapshot_name: str = ""


RESTORE_LKG_PHRASE = "RESTORE_WININET_PROXY_FROM_LKG"


@router.post("/api/proxy/restore-lkg")
def api_proxy_restore_lkg(
    body: RestoreLkgRequest,
    _user: AuthUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Preview or apply HKCU WinINET restore from latest known-good snapshot via the CLI confirmation gate.

    Subprocess exit codes (``python -m src proxy restore-lkg``), aligned with
    :func:`src.command_handlers_safety.cmd_proxy_restore_lkg` and
    :func:`src.core.windows_cli.exit_code_if_not_windows`:

    * ``0`` — success path (e.g. PREVIEW) or live restore succeeded.
    * ``1`` — blocked / failed (no LKG, bad confirmation, mutation failed, etc.).
    * ``2`` — non-Windows host when a live execute was requested (typed BLOCK with JSON body).

    Any other exit code still fails the HTTP handler (see :func:`_invoke_src_json_status`).
    """

    argv = [
        "proxy",
        "restore-lkg",
        "--json",
        "--dry-run",
        "true" if body.dry_run else "false",
    ]
    if body.confirmation:
        argv.extend(["--confirm", body.confirmation])
    if body.snapshot_name:
        argv.extend(["--name", body.snapshot_name])
    # {0,1,2} matches cmd_proxy_restore_lkg; 2 is not argparse noise here — it is
    # exit_code_if_not_windows(...) when dry_run is false on a non-Windows OS.
    return _invoke_src_json_status(argv, allowed_returncodes={0, 1, 2})


@router.post("/api/proxy/config-check")
def api_proxy_config_check(_user: AuthUser = Depends(get_current_user)) -> dict[str, Any]:
    """Read-only proxy config audit (WinINET, WinHTTP, Git, npm, env, browser policy)."""

    return _invoke_src_json(["proxy", "config-check", "--json"])


class RegistryWriterProofRequest(BaseModel):
    """Represent registry writer proof request data used by the toolkit.
    
    Attributes:
        since_seconds: Field or variant describing since seconds evidence or state.
        procmon_csv: Field or variant describing procmon csv evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    since_seconds: int = 120
    procmon_csv: str | None = None


@router.post("/api/proxy/registry-writer-proof")
def api_proxy_registry_writer_proof(
    body: RegistryWriterProofRequest,
    _user: AuthUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Read-only Sysmon / Security 4657 / Procmon CSV registry writer evidence."""

    argv = [
        "proxy",
        "registry-writer-proof",
        "--json",
        "--since-seconds",
        str(int(body.since_seconds)),
    ]
    if body.procmon_csv:
        argv.extend(["--procmon-csv", body.procmon_csv])
    return _invoke_src_json(argv)
