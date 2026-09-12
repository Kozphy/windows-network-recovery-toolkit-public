# Frontend (Next.js)

Optional **local demo UI** for the FastAPI backend. Not a published production tenant unless you deploy it yourself (e.g. Vercel).

---

## Purpose

- Visualize diagnosis history, usage, and billing demo flows when Supabase auth is configured
- Call backend routes via `frontend/lib/api.ts` (`authFetch` helper with Bearer token)

**Does not:** run endpoint remediation, mutate Windows registry, or replace CLI governance reports.

---

## Run locally

```bash
npm install
npm run dev
```

Default dev server: **http://localhost:3000** (Next.js). Backend expected at `NEXT_PUBLIC_API_BASE` (default `http://localhost:8000`).

Start the API first:

```powershell
.\start-api.ps1
```

---

## Environment

Copy `.env.local.example` to `.env.local` and set:

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL (auth demo) |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase anon key |
| `NEXT_PUBLIC_API_BASE` | FastAPI origin (default `http://localhost:8000`) |

Technology-risk read-only routes (`GET /trisk/*`) typically work without auth in local demo mode.

---

## API usage (verified)

See TSDoc on `frontend/lib/api.ts`:

- Authenticated: `authFetch(path, token, options)` — throws on non-2xx
- Read-only TRISK examples: `/trisk/health`, `/incidents`, `/risks`, `/controls`, `/reports/executive`

---

## Safety boundaries

- UI displays backend policy decisions — **does not** bypass typed confirmation for remediation execute.
- Error strings from `authFetch` may include response bodies — avoid logging tokens in production.

---

## Deploy (optional)

- Vercel (common MVP path)
- Configure environment variables in project settings
- Set `NEXT_PUBLIC_API_BASE` to your hosted FastAPI URL

---

## Related docs

- [docs/platform_api_contract.md](../docs/platform_api_contract.md)
- [backend/README.md](../backend/README.md)
