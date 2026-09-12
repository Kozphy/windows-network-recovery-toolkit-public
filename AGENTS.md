# AGENTS.md — public mirror

Short rules for AI assistants working in the **public** edition.

## What this repo is

Public sanitized mirror: Windows endpoint evidence CLI + fixture-mode demo API/frontend.

**Not** the private monorepo (enterprise SaaS, Stripe, fleet, OpenClaw stay private).

## Non-negotiable rules

1. Evidence tiers and ordinal confidence — no false certainty
2. Remediation is policy-gated; dry-run / preview by default
3. Never change risky Windows/network state without explicit confirmation + typed token
4. Prefer deterministic fixtures over live speculation
5. Do not commit secrets, `.audit/`, logs, or generated junk

## Quick commands

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m windows_network_toolkit proxy-status --fixture examples/evidence/DEAD_PROXY_CONFIG.json
python -m windows_network_toolkit dns-edge-fix --dry-run true
$env:PLATFORM_FIXTURE_MODE = "1"
python -m uvicorn backend.public_app:app --host 127.0.0.1 --port 8000
```

Confirmation tokens: `DISABLE_WININET_PROXY`, `PREFER_IPV4_OVER_IPV6`, `RESTORE_IPV6_PREFERENCE`, `FIX_ERR_NAME_NOT_RESOLVED`.

## Sync

Private → public export is one-way via `tools/export_public_mirror.py` in the private monorepo. See [docs/private-public-split.md](docs/private-public-split.md).
