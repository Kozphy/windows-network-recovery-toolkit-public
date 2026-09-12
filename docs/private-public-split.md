# Private monorepo vs public CLI/demo mirror

This repository is the **private** source of truth. A sanitized **public** GitHub
repo publishes the core Windows CLI plus a read-only fixture-mode demo API and
frontend.

## Ownership

| Surface | Repo |
|---------|------|
| Full product (SaaS, Stripe, fleet, OpenClaw, internal case studies) | **Private** monorepo (this repo) |
| CLI + fixture demo API/frontend | **Public** mirror (`windows-network-recovery-toolkit-public`) |

Locked product decision: **two repos** · public scope = **CLI + demo API/frontend**.

## What never leaves private

- Stripe / billing / SaaS auth secrets and routes
- Fleet multi-tenant and SRE write surfaces not needed for fixture demos
- OpenClaw coding agent and `skills/`
- Operator `.audit/`, `logs/`, `platform_data*`, real `.env*`
- Personal Windows paths, real incident ports, PII in case studies
- `.worktrees/`, local pytest temp dirs

Allowlist and exclude globs: [`config/public_mirror_manifest.yaml`](../config/public_mirror_manifest.yaml).

## Export workflow (private → public)

From the private monorepo root:

```powershell
$env:PYTHONPATH = (Get-Location).Path

# Build sanitized tree
python tools/export_public_mirror.py --out .public_mirror_export --print-bootstrap

# Build + run audit/pytest gates inside the export
python tools/export_public_mirror.py --out .public_mirror_export --run-checks
```

The exporter:

1. Copies `include_paths` from the manifest
2. Deletes `exclude_globs` matches
3. Rewrites `README.md`, `pyproject.toml`, `AGENTS.md` from [`config/public_mirror/`](../config/public_mirror/)
4. Ensures [`backend/public_app.py`](../backend/public_app.py) is present (fixture/read-only FastAPI app)

Hygiene before any publish:

```powershell
python tools/public_release_audit.py --tracked-only
python tools/cleanup_generated.py --apply
```

Also see [`PUBLIC_RELEASE_CHECKLIST.md`](../PUBLIC_RELEASE_CHECKLIST.md).

## Public demo entrypoints

```powershell
# CLI
python -m windows_network_toolkit dns-edge-status
python -m windows_network_toolkit ipv6-path

# API (loopback, fixture mode)
$env:PLATFORM_FIXTURE_MODE = "1"
python -m uvicorn backend.public_app:app --host 127.0.0.1 --port 8000
# or: $env:WNRT_PUBLIC_API = "1"; python -m backend

# Frontend
cd frontend
copy .env.local.example .env.local
npm run dev
```

## One-time public repo bootstrap

Create an empty **public** GitHub repository, then push the export (no secrets):

```powershell
gh repo create Kozphy/windows-network-recovery-toolkit-public --public `
  --description "Public mirror: WNRT CLI + fixture demo API"

python tools/export_public_mirror.py --out .public_mirror_export --run-checks
cd .public_mirror_export
git init -b main
git add .
git commit -m "Initial public mirror export from private monorepo."
git remote add origin git@github.com:Kozphy/windows-network-recovery-toolkit-public.git
git push -u origin main
```

Enable GitHub Actions using the copied [`.github/workflows/public-mirror-ci.yml`](../.github/workflows/public-mirror-ci.yml).

## Subsequent syncs

1. Land changes in **private** first.
2. Re-run `python tools/export_public_mirror.py --out <public-checkout-or-export> --run-checks`.
3. Commit and push on the **public** remote only after audit is clean.
4. Prefer **cherry-picking** public community fixes into private after review — never reverse-sync secrets or private-only modules from public PRs without review.

## Safety invariants (both editions)

- Remediation dry-run by default; typed confirmation tokens required for live apply
- Public demo API remains fixture/read-only — no silent registry/firewall/adapter mutation
- Epistemic wording and `limitations[]` preserved

## Out of scope

- Publishing to PyPI (follow-on)
- Making this private monorepo public
- Full enterprise feature parity in the public mirror
