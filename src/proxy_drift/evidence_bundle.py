"""Collect a read-only proxy/network evidence bundle."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.proxy_drift.boot_trace import run_boot_trace_loop
from src.proxy_drift.safe_search import safe_search
from src.proxy_drift.startup_inventory import collect_startup_inventory


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bundle_name() -> str:
    return datetime.now().strftime("evidence-bundle-%Y%m%d-%H%M%S")


def _run_text(argv: list[str], *, cwd: Path) -> str:
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, shell=False, timeout=120)
    return ((proc.stdout or "") + (proc.stderr or "")).strip()


def collect_evidence_bundle(
    *,
    repo_root: Path,
    bundle_dir: Path | None = None,
    boot_duration: int = 30,
    boot_interval: int = 2,
) -> dict[str, Any]:
    """Collect a read-only evidence bundle into a report directory.

    Args:
        repo_root: Repository root used as command working directory.
        bundle_dir: Optional output directory; defaults under ``reports`` with a timestamped name.
        boot_duration: Duration in seconds for the embedded boot trace run.
        boot_interval: Sampling interval in seconds for the embedded boot trace run.

    Returns:
        Dict with schema version, timestamp, bundle directory, files written, and limitations.

    Side effects:
        Creates the bundle directory, writes evidence files, runs read-only CLI commands, and performs DNS/look-up probes.

    Audit Notes:
        The bundle is observational endpoint evidence; DNS and listener data do not prove registry writer identity."""
    repo_root = repo_root.resolve()
    out_dir = (bundle_dir or (repo_root / "reports" / _bundle_name())).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    py = repo_root / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        py = Path("python")

    (out_dir / "proxy-health.txt").write_text(
        _run_text([str(py), "-m", "windows_network_toolkit", "proxy-health"], cwd=repo_root),
        encoding="utf-8",
    )
    (out_dir / "proxy-status.txt").write_text(
        _run_text([str(py), "-m", "windows_network_toolkit", "proxy-status"], cwd=repo_root),
        encoding="utf-8",
    )
    (out_dir / "proxy-path-status.txt").write_text(
        _run_text([str(py), "-m", "src", "proxy-path-status"], cwd=repo_root),
        encoding="utf-8",
    )
    (out_dir / "proxy-owner.json").write_text(
        _run_text([str(py), "-m", "windows_network_toolkit", "proxy-owner"], cwd=repo_root),
        encoding="utf-8",
    )
    (out_dir / "proxy-diagnose.txt").write_text(
        _run_text([str(py), "-m", "src", "proxy-diagnose"], cwd=repo_root),
        encoding="utf-8",
    )

    startup_payload = collect_startup_inventory(repo_root=repo_root, audit_path=repo_root / "logs" / "startup_inventory.jsonl")
    import json

    (out_dir / "startup-inventory.json").write_text(json.dumps(startup_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    search_payload = safe_search(query="proxy", target="project", repo_root=repo_root)
    (out_dir / "safe-search-proxy.json").write_text(json.dumps(search_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    winhttp = subprocess.run(["netsh", "winhttp", "show", "proxy"], capture_output=True, text=True, shell=False, timeout=60)
    (out_dir / "winhttp.txt").write_text(((winhttp.stdout or "") + (winhttp.stderr or "")).strip(), encoding="utf-8")
    reg = subprocess.run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"],
        capture_output=True,
        text=True,
        shell=False,
        timeout=60,
    )
    (out_dir / "wininet-registry.txt").write_text(((reg.stdout or "") + (reg.stderr or "")).strip(), encoding="utf-8")

    dns_hosts = ["hr.esunfhc.com", "recruit.esunbank.com.tw", "www.esunbank.com.tw", "www.microsoft.com"]
    dns_lines: list[str] = []
    for host in dns_hosts:
        proc = subprocess.run(["nslookup", host, "8.8.8.8"], capture_output=True, text=True, shell=False, timeout=30)
        dns_lines.append(f"=== {host} ===")
        dns_lines.append(((proc.stdout or "") + (proc.stderr or "")).strip())
    (out_dir / "dns-lookups.txt").write_text("\n".join(dns_lines).strip() + "\n", encoding="utf-8")

    trace = run_boot_trace_loop(
        duration_seconds=float(boot_duration),
        interval_seconds=float(boot_interval),
        audit_path=out_dir / "proxy_boot_trace.jsonl",
    )
    (out_dir / "proxy-boot-trace-run.txt").write_text(
        f"Boot trace complete — {trace.get('samples_collected')} samples\nAudit: {trace.get('audit_path')}\n",
        encoding="utf-8",
    )

    for log_name in ("proxy_guardian.jsonl", "proxy_guard.jsonl", "startup_inventory.jsonl"):
        source = repo_root / "logs" / log_name
        if source.exists():
            lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()[-20:]
            (out_dir / f"{log_name}.tail").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    return {
        "schema_version": "evidence_bundle.v1",
        "timestamp_utc": _now(),
        "bundle_dir": str(out_dir),
        "files_written": sorted(p.name for p in out_dir.iterdir() if p.is_file()),
        "limitations": [
            "Bundle is read-only endpoint evidence; it is not registry writer proof.",
            "DNS and listener correlation remain observational.",
        ],
    }
