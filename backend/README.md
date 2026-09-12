# Backend (FastAPI)

FastAPI application for **technology risk analytics** and the optional **Endpoint Reliability Platform** prototype. Serves read-only `/trisk/*` routes, policy-gated `/platform/*` routes, and enterprise ingest under `/v1/enterprise/*` when configured.

**This is not a hosted SaaS by default** — local demo uses SQLite or fixture mode unless you run `docker-compose.yml` with Postgres.

---

## Ten-minute orientation

| Layer | Path | Responsibility |
|-------|------|----------------|
| Entry | `backend/main.py` | App factory, router mounts, `/metrics` merge |
| TRISK API | `backend/canonical_routes.py`, `backend/trisk_metrics.py` | Read-only incidents, risks, controls, executive report |
| Platform API | `backend/platform_routes.py` | JSONL-backed fleet, diagnosis, remediation preview/execute gates |
| Enterprise | `backend/services/` | Evidence ingest, classification pipeline, audit service |
| Persistence | `backend/db/` | SQLModel tables (`trisk_*`); URL from `TRISK_DATABASE_URL` |
| Platform files | `platform_core/storage.py` | Append-only `platform_data/*.jsonl` |

---

## Run locally (Windows)

Use the **project virtual environment**. If `uvicorn` comes from another venv (e.g. Hermes agent), imports like `stripe` may fail even though this repo lists them in `pyproject.toml`.

```powershell
# From repo root — one-time setup
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Start API (fixture-safe demo)
$env:PYTHONPATH = (Get-Location).Path
$env:PLATFORM_FIXTURE_MODE = "1"
.\start-api.ps1
# or: .\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Helper scripts (see safety headers in each file):

```powershell
.\scripts\run-backend.ps1
.\scripts\run-backend.ps1 -Reload
.\scripts\stop-backend.ps1
```

Open **http://127.0.0.1:8000/docs** for OpenAPI.

---

## Run locally (Unix / Make)

```bash
pip install -r requirements.txt
make demo-api
```

---

## API surfaces (verified routes)

| Prefix | Auth | Mutation default | Notes |
|--------|------|------------------|-------|
| `GET /trisk/*` | Optional token in demo | Read-only | Technology risk portfolio API |
| `GET /health` | None | Read-only | Liveness |
| `GET /metrics` | None | Read-only | Prometheus text + in-memory counters |
| `/platform/*` | `X-Api-Role` headers | Preview-only; execute gated | See `docs/platform_api_contract.md` |
| `/v1/enterprise/*` | `X-Api-Token` | Ingest writes DB; remediation preview-only | SQLModel persistence |
| `/diagnose`, `/history` | Supabase JWT | Writes usage rows when configured | Optional SaaS demo |

Remediation **execute** paths require typed confirmation and policy allow — they do not run autonomously.

---

## Environment

Copy `.env.example` to `.env` and set as needed:

| Variable | Purpose |
|----------|---------|
| `TRISK_DATABASE_URL` | SQLModel engine URL; default local `sqlite:///./trisk_local.db` (gitignored) |
| `TRISK_API_TOKEN` | `/v1/*` demo token (default `dev-trisk-token`) |
| `PLATFORM_DATA_DIR` | Override `platform_data/` JSONL root |
| `PLATFORM_FIXTURE_MODE` | `1` — fixture-safe responses for demos |
| `SUPABASE_JWT_SECRET` | SaaS JWT routes (`/diagnose`, `/history`) |
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | Billing demo only |
| `CORS_ALLOW_ORIGINS` | Comma-separated origins for hosted UIs |
| `QUEUE_BACKEND` | `memory` (tests) or `redis` (compose stack) |

Billing routes return **503** when the `stripe` package is missing; `/v1/*` and `/platform/*` still load.

---

## Persistence

| Store | When used | Audit notes |
|-------|-----------|-------------|
| `trisk_local.db` | Local dev without Docker | SQLite file at repo root; tests use ephemeral `trisk.db` in `tmp_path` |
| Postgres (`docker-compose.yml`) | Production-shaped demo | Schema in `backend/db/schema.sql` |
| `platform_data/*.jsonl` | Platform prototype | Append-only; correlate `audit.jsonl` with `remediation_executions.jsonl` |

Tests reset the engine via `tests/backend/conftest.py` — do not point CI at a shared production database.

---

## Docker

| Stack | File | Services |
|-------|------|----------|
| Full platform | `docker-compose.yml` | API + Postgres + Prometheus + Grafana |
| Reviewer demo | `docker-compose.demo.yml` | API only (`DEMO_MODE=true`) |

See [docs/docker-demo.md](../docs/docker-demo.md).

---

## Safety boundaries

- Platform remediation defaults to **dry-run** and **preview-only** policy outcomes.
- `/trisk/*` and portfolio metrics are **read-only** — no registry or network mutation from those routes.
- AI explanation endpoints do **not** authorize execution (see `docs/security-review.md`).

---

## Tests

```powershell
pytest -q tests/backend/
pytest -q tests/security/test_security_review_pack.py
```

---

## Deploy (optional)

- Railway or Render (MVP sketches in docs — not bundled automation)
- Set env vars in hosting dashboard
- Use managed Postgres for multi-tenant demos; SQLite is local-only
