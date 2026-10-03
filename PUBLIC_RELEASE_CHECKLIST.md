# Public release checklist

Use this checklist before publishing to the **public mirror** repo
(`windows-network-recovery-toolkit-public`). This private monorepo stays private.

Canonical dual-repo workflow: [docs/private-public-split.md](docs/private-public-split.md).

Automated helpers:

```powershell
python tools/export_public_mirror.py --out .public_mirror_export --run-checks
python tools/public_release_audit.py --tracked-only
python tools/cleanup_generated.py --apply
python tools/public_release_audit.py --include-untracked
pytest -q tests/test_public_release_audit.py tests/test_export_public_mirror.py tests/test_policy_safety_contract.py tests/test_api_dry_run_default.py
```

---

## A. Privacy cleanup

- [ ] No real `logs/` or `reports/` content committed
- [ ] No real `platform_data/` or `platform_data_fleet_demo/` JSONL
- [ ] No `*.jsonl` outside `tests/fixtures/`, `examples/`, `demo_data/`
- [ ] No `config/last_known_good_proxy.json` (use `config/last_known_good_proxy.example.json`)
- [ ] No `.env` / `.env.local` (only `*.env.example`)
- [ ] No real usernames in docs (use `demo-user`)
- [ ] No real Windows paths (`C:/Users/...`) in committed docs or config
- [ ] No real incident proxy ports in case studies (use demo port e.g. `54321`)
- [ ] No API keys, tokens, passwords, or personal email in tree
- [ ] No personal screenshots or machine-specific artifacts
- [ ] `python tools/public_release_audit.py --tracked-only` exits 0 (use `--include-untracked` for local hygiene)

---

## B. Safety cleanup

- [ ] No silent process kill paths (registry + tests)
- [ ] No silent registry mutation (typed confirmation required)
- [ ] Firewall reset is manual-only / blocked at API execute
- [ ] Adapter disable forbidden at registry level
- [ ] `ExecuteIn.dry_run` defaults to `True` — verified by tests
- [ ] Arbitrary shell blocked (`tests/test_policy_safety_contract.py`)
- [ ] `make demo` runs golden fixture replay without host mutation
- [ ] `python -m toolkit audit verify logs/canonical_decision_audit.jsonl` passes on fresh chain
- [ ] Bad-gateway diagnose is read-only (`windows_network_toolkit bad-gateway-diagnose`)
- [ ] `docs/START_HERE.md` and `docs/safety_doctrine.md` present

---

## C. Engineering readiness

- [ ] `pip install -e ".[dev]"`
- [ ] `pytest -q` passes (note: known legacy failures if any — document in PR)
- [ ] `ruff check platform_core backend evidence failure_system tests tools`
- [ ] `black --check platform_core backend evidence failure_system tests tools`
- [ ] `mypy` (scoped) passes if configured
- [ ] [docs/demo_3_minute.md](docs/demo_3_minute.md) works from clean clone
- [ ] All committed fixtures are synthetic / fictional
- [ ] GitHub Actions CI green on PR

---

## D. Portfolio readiness

- [ ] README one-liner and privacy note present
- [ ] [docs/demo_3_minute.md](docs/demo_3_minute.md)
- [ ] [docs/architecture_platform.md](docs/architecture_platform.md)
- [ ] [docs/safety_model.md](docs/safety_model.md)
- [ ] [docs/interview_case_study_tier1.md](docs/interview_case_study_tier1.md)
- [ ] [docs/production_readiness.md](docs/production_readiness.md)
- [ ] [SECURITY.md](SECURITY.md) updated
- [ ] [docs/adr/](docs/adr/) present

---

## E. Two-repo mirror (private → public)

- [ ] Change landed and reviewed in the **private** monorepo first
- [ ] `python tools/export_public_mirror.py --out .public_mirror_export --run-checks` exits 0
  (its first gate is a full-tree `public_release_audit --include-untracked` of the export)
- [ ] Medium audit findings in the export (emails, private IPs) reviewed and confirmed synthetic
- [ ] `git status` inside `.public_mirror_export` shows no private-only paths
  (`backend/billing.py`, `**/openclaw/**`, `skills/`, `.audit/`, `logs/`, `reports/`, `platform_data*`, real `.env*`)
- [ ] New top-level surfaces were added to `config/public_mirror_manifest.yaml` deliberately (allowlist, not denylist)
- [ ] Push goes to `Kozphy/windows-network-recovery-toolkit-public` only — never push this private repo to the public remote
- [ ] Public PR fixes are cherry-picked back into private after review (no blind reverse sync)

---

## Commands before push

```powershell
python tools/public_release_audit.py --tracked-only
python tools/cleanup_generated.py
python tools/cleanup_generated.py --apply
git status
```

After review:

```powershell
# Export sanitized public tree, then push the PUBLIC remote (not this private repo)
python tools/export_public_mirror.py --out .public_mirror_export --run-checks --print-bootstrap
# Follow printed bootstrap / sync commands for Kozphy/windows-network-recovery-toolkit-public
```

---

## Synthetic data locations

| Path | Purpose |
|------|---------|
| `tests/fixtures/` | Automated test inputs |
| `examples/` | Documentation samples |
| `demo_data/manifest.json` | Demo scenario catalog |
| `config/*.example.json` | Config templates |

Do **not** commit operator-generated snapshots from your machine.
