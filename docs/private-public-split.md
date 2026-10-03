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

1. Empties `--out` (default behaviour; `--no-clean` skips this) while keeping any
   `.git` directory, so a public-repo checkout can be re-exported in place and
   files removed from the allowlist also disappear from the public tree
2. Copies `include_paths` from the manifest
3. Deletes `exclude_globs` matches
4. Rewrites `README.md`, `pyproject.toml`, `AGENTS.md` from [`config/public_mirror/`](../config/public_mirror/)
5. Writes `.public_mirror.json` edition metadata
6. Ensures [`backend/public_app.py`](../backend/public_app.py) is present (fixture/read-only FastAPI app)

With `--run-checks` it then runs the manifest `required_checks` inside the export
and exits non-zero on the first failure:

1. `public_release_audit --include-untracked` — scans **every** exported file,
   before any test writes artifacts. (`--tracked-only` would scan nothing here:
   the export has no tracked files of its own.) High-risk findings fail the gate;
   medium findings such as synthetic fixture emails or RFC1918 demo IPs are
   reported for review.
2. Policy safety, DNS-edge/IPv6, and backend API contract pytest slices. These
   write `.audit/` and `.pytest_tmp/` into the export; both are gitignored there,
   so `git add -A` does not publish them.

Hygiene in the private repo before exporting:

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
2. Re-export into the public checkout (its `.git` is preserved; everything else is rebuilt):

   ```powershell
   python tools/export_public_mirror.py --out .public_mirror_export --run-checks
   ```

3. Review and push on the **public** remote only after the checks pass:

   ```powershell
   cd .public_mirror_export
   git status
   git add -A
   git commit -m "Sync public mirror from private monorepo."
   git push
   ```

4. Prefer **cherry-picking** public community fixes into private after review — never reverse-sync secrets or private-only modules from public PRs without review.

`.public_mirror_export/` is gitignored in the private repo, so the nested public
checkout is never committed here. Never push the private repo to the public remote.

## Safety invariants (both editions)

- Remediation dry-run by default; typed confirmation tokens required for live apply
- Public demo API remains fixture/read-only — no silent registry/firewall/adapter mutation
- Epistemic wording and `limitations[]` preserved

## Out of scope

- Publishing to PyPI (follow-on)
- Making this private monorepo public
- Full enterprise feature parity in the public mirror
