"""Classification rule helpers — neutral language only."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from src.proxy_guard.proxy_allowlist import ProxyAllowlist, allowlist_match_summary

if TYPE_CHECKING:
    from .models import ProcessClassificationInput

_SECURITY_TOOLS = frozenset(
    {"fiddler.exe", "charles.exe", "mitmproxy.exe", "burpsuite.exe", "proxifier.exe"}
)
_DEV_KEYWORDS = frozenset({"npm", "vite", "next", "webpack", "pnpm", "yarn", "npx", "dev-server", "devserver"})
_OBFUSCATION = (
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "bypass",
    "windowstyle hidden",
    "-w hidden",
)
_SUSPICIOUS_PATHS = ("\\temp\\", "\\downloads\\", "\\appdata\\roaming\\", "\\appdata\\local\\temp\\")
_BROWSER_NAMES = frozenset({"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"})


def basename(path: str | None) -> str:
    """Basename.
    
    Args:
        path: Filesystem path used by the operation.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    if not path:
        return ""
    return path.replace("/", "\\").split("\\")[-1].lower()


def path_low(path: str | None) -> str:
    """Path low.
    
    Args:
        path: Filesystem path used by the operation.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    return (path or "").replace("/", "\\").lower()


def is_localhost_proxy(proxy: str | None) -> bool:
    """Is localhost proxy.
    
    Args:
        proxy: The proxy value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if not proxy:
        return False
    low = proxy.strip().lower()
    return low.startswith("127.") or low.startswith("localhost") or low.startswith("[::1]")


def is_external_proxy(proxy: str | None) -> bool:
    """Is external proxy.
    
    Args:
        proxy: The proxy value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return bool(proxy and proxy.strip() and not is_localhost_proxy(proxy))


def is_unsigned(signature_status: str | None) -> bool:
    """Is unsigned.
    
    Args:
        signature_status: The signature status value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if not signature_status:
        return True
    low = signature_status.lower()
    if "unsigned" in low or "not signed" in low:
        return True
    if "signed" in low:
        return False
    return True


def obfuscated_command(cmd: str | None) -> bool:
    """Obfuscated command.
    
    Args:
        cmd: The cmd value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if not cmd:
        return False
    low = cmd.lower()
    if any(m in low for m in _OBFUSCATION):
        return True
    return bool(re.search(r"[A-Za-z0-9+/]{80,}={0,2}", cmd))


def suspicious_launch_path(inp: ProcessClassificationInput) -> bool:
    """Suspicious launch path.
    
    Args:
        inp: The inp value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    paths = (path_low(inp.image_path), path_low(inp.parent_image_path), path_low(inp.working_directory))
    if basename(inp.parent_image_path) != "powershell.exe":
        return False
    if basename(inp.image_path) != "node.exe":
        return any(any(m in p for m in _SUSPICIOUS_PATHS) for p in paths if p)
    return any(any(m in p for m in _SUSPICIOUS_PATHS) for p in paths if p)


def cursor_context(inp: ProcessClassificationInput, allowlist: ProxyAllowlist) -> bool:
    """Cursor context.
    
    Args:
        inp: The inp value supplied by the caller.
        allowlist: The allowlist value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    blobs = " ".join(
        filter(
            None,
            (
                path_low(inp.image_path),
                path_low(inp.parent_image_path),
                (inp.parent_command_line or "").lower(),
                (inp.command_line or "").lower(),
            ),
        )
    )
    if "cursor" in blobs:
        return True
    match = allowlist_match_summary(
        process_name=basename(inp.parent_image_path) or basename(inp.image_path),
        executable_path=inp.parent_image_path or inp.image_path,
        command_line=inp.parent_command_line,
        allowlist=allowlist,
    )
    return match["trusted_path_prefix"] and "cursor" in blobs


def vscode_context(inp: ProcessClassificationInput, allowlist: ProxyAllowlist) -> bool:
    """Vscode context.
    
    Args:
        inp: The inp value supplied by the caller.
        allowlist: The allowlist value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if basename(inp.parent_image_path) == "code.exe":
        return True
    parent_path = path_low(inp.parent_image_path)
    if parent_path and ("\\microsoft vs code\\" in parent_path or parent_path.endswith("\\code.exe")):
        return True
    cmd_blob = f"{inp.parent_command_line or ''} {inp.command_line or ''}".lower()
    if "vscode" in cmd_blob or "visual studio code" in cmd_blob:
        return True
    if "extension" in cmd_blob and ("code.exe" in cmd_blob or "vscode" in cmd_blob):
        return True
    match = allowlist_match_summary(
        process_name="code.exe",
        executable_path=inp.parent_image_path or "",
        command_line=inp.parent_command_line or inp.command_line,
        allowlist=allowlist,
    )
    return match["trusted_path_prefix"] and bool(parent_path)


def dev_proxy_context(inp: ProcessClassificationInput) -> bool:
    """Dev proxy context.
    
    Args:
        inp: The inp value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    cmd = (inp.command_line or "").lower()
    if any(k in cmd for k in _DEV_KEYWORDS):
        return True
    cwd = (inp.working_directory or "").lower()
    return bool(cwd and any(x in cwd for x in ("\\projects\\", "\\repos\\", "\\dev\\", "\\src\\")))


def autoconfig_changed(inp: ProcessClassificationInput) -> bool:
    """Autoconfig changed.
    
    Args:
        inp: The inp value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    v = (inp.registry_value_name or inp.registry_target or "").lower()
    return "autoconfigurl" in v


def nvidia_python_false_positive(inp: ProcessClassificationInput) -> bool:
    """Nvidia python false positive.
    
    Args:
        inp: The inp value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if basename(inp.image_path) != "python.exe":
        return False
    blob = f"{inp.command_line or ''} {inp.parent_command_line or ''}".lower()
    return "nvidia" in blob and not inp.has_registry_writer_proof


def system_writer(inp: ProcessClassificationInput) -> bool:
    """System writer.
    
    Args:
        inp: The inp value supplied by the caller.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    name = basename(inp.image_path)
    return name in ("reg.exe", "svchost.exe", "dllhost.exe") and inp.has_registry_writer_proof
