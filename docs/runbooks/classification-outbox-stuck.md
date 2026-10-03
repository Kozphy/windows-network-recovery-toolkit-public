# Runbook: classification outbox stuck pending

## Purpose

Restore classification enqueue when durable outbox rows remain `pending` after
evidence commit, without re-posting evidence or weakening remediation gates.

## Privileges

- Admin V1 principal (`X-Api-Role: admin` + valid `X-Api-Token` / tenant headers
  as configured for the demo control plane).
- Ability to set process env and restart the API when changing feature flags.

## Safety boundaries

- Do **not** treat heartbeat `ONLINE_UNASSESSED` as classification health.
- Do **not** weaken dry-run / remediation policy gates while clearing backlog.
- Prefer sweep / flag fix over duplicate evidence POST (ingest is idempotent but unnecessary).

## Symptoms

- Agent evidence returns `202` with `job_id: null` and `classification_status: pending`
- Endpoint detail stays `NOT_ASSESSED` / no incident after ingest
- `GET /v1/classification-outbox/status` shows `pending_count > 0` or growing `oldest_pending_age_seconds`
- `GET /metrics` shows rising `classification_outbox_dispatch_failures_total` or non-zero `classification_outbox_pending`

## Quick checks (observation)

1. Confirm dispatch flag:
   ```powershell
   # Expect true unless deliberately disabled for a drill
   echo $env:TRISK_OUTBOX_DISPATCH_ENABLED
   ```
2. Status snapshot (admin token):
   ```powershell
   curl -s http://127.0.0.1:8000/v1/classification-outbox/status `
     -H "X-Api-Token: $env:TRISK_API_TOKEN" `
     -H "X-Api-Role: admin" `
     -H "X-Api-Tenant: <tenant>"
   ```
3. Note `pending_at_or_above_max_attempts` — poison rows need manual inspection of `last_error`, not blind retries forever.

## Recovery

1. If flag was left off after a drill, set `TRISK_OUTBOX_DISPATCH_ENABLED=true` and restart the API process if env is loaded at boot.
2. Optionally enable continuous recovery: `TRISK_OUTBOX_SWEEPER_ENABLED=true` (default off) and restart; confirm `sweeper_thread_alive` via status.
   Automatic retries use capped exponential backoff (`TRISK_OUTBOX_RETRY_BASE_SECONDS=5`,
   `TRISK_OUTBOX_RETRY_MAX_SECONDS=300` by default). An explicit admin sweep bypasses
   that delay after the queue has been repaired.
3. Sweep pending rows (oldest first):
   ```powershell
   curl -s -X POST http://127.0.0.1:8000/v1/classification-outbox/sweep `
     -H "Content-Type: application/json" `
     -H "X-Api-Token: $env:TRISK_API_TOKEN" `
     -H "X-Api-Role: admin" `
     -H "X-Api-Tenant: <tenant>" `
     -d '{"limit": 50, "max_attempts": 20, "force": false}'
   ```
4. If the flag must stay off temporarily but backlog must drain (recovery drill), use `"force": true`.
5. Re-check status and a known endpoint:
   ```powershell
   curl -s http://127.0.0.1:8000/v1/endpoints/<endpoint_id> `
     -H "X-Api-Token: $env:TRISK_API_TOKEN" `
     -H "X-Api-Role: admin" `
     -H "X-Api-Tenant: <tenant>"
   ```

## Idempotency

- Re-running sweep on already-`dispatched` rows is a no-op (they are not selected).
- Force sweep while flag is off still enqueues; leave `force: false` in normal ops.

## Agent credential recovery (related)

- Rotate without re-enroll: `POST /v1/agents/credentials/rotate` with `Authorization: Agent <current-secret>`
- Admin revoke: `POST /v1/endpoints/<endpoint_id>/credentials/revoke`
- Admin reissue same endpoint: `POST /v1/endpoints/<endpoint_id>/credentials/reissue`

## Do not

- Re-post evidence as the primary fix when the outbox row already exists (duplicate ingest is idempotent but unnecessary).
- Treat heartbeat `ONLINE_UNASSESSED` as classification health.
- Weaken dry-run / remediation gates while clearing backlog.

## Related

- [SLO snippet](../ops/slo-classification-outbox.md)
- [Failure drill postmortem](../ops/failure-drill-classification-outbox.md)
- [YC P0 productization audit](../yc-p0-productization-audit.md)
