"use client";

/**
 * Operator-facing Next.js dashboard for the optional Endpoint Reliability Platform prototype (`/platform/*`).
 *
 * Summarizes localhost FastAPI payloads (health, metrics, previews) so demos avoid manual `curl` flows.
 *
 * @remarks Placement: `frontend/app/platform/page.tsx` route component.
 * Hits `NEXT_PUBLIC_PLATFORM_API` over HTTP only (no SQLite or local batch execution).
 *
 * @remarks Requires `NEXT_PUBLIC_PLATFORM_API`; when unset, surfaces an explicit banner instead of empty fetches.
 * RBAC-lite headers (`PLATFORM_DEMO_RBAC_ROLE` persisted in `localStorage`) mimic backend `X-Operator-Role`.
 *
 * @remarks Mutation paths call FastAPI remediation routes only; never shells to `scripts/*.bat`.
 * Correlate KPI mismatches with backend `PLATFORM_DATA_DIR` drift or stale operator headers—not silent frontend failure by default.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

const base =
  typeof process !== "undefined" && process.env.NEXT_PUBLIC_PLATFORM_API
    ? process.env.NEXT_PUBLIC_PLATFORM_API.replace(/\/$/, "")
    : "";

const DEMO_ROLE_KEY = "PLATFORM_DEMO_RBAC_ROLE";

export default function PlatformPage() {
  const [role, setRoleState] = useState<string>("admin");
  useEffect(() => {
    if (typeof window !== "undefined") {
      setRoleState(window.localStorage.getItem(DEMO_ROLE_KEY) || "admin");
    }
  }, []);

  const setRole = useCallback((r: string) => {
    setRoleState(r);
    if (typeof window !== "undefined") window.localStorage.setItem(DEMO_ROLE_KEY, r);
  }, []);

  const headers = useMemo(() => {
    const h: Record<string, string> = {
      "X-Operator-Role": role,
      "X-Operator-Id": "nextjs-platform-ui",
    };
    return h;
  }, [role]);

  const [health, setHealth] = useState<object | null>(null);
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const [endpoints, setEndpoints] = useState<object | null>(null);
  const [failureEvents, setFailureEvents] = useState<object | null>(null);
  const [audit, setAudit] = useState<object | null>(null);
  const [previewResult, setPreviewResult] = useState<string>("");
  const [normEventsPayload, setNormEventsPayload] = useState<object | null>(null);
  const [policySummary, setPolicySummary] = useState<object | null>(null);
  const [replayOutput, setReplayOutput] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [incidentsPayload, setIncidentsPayload] = useState<object | null>(null);
  const [timelineNote, setTimelineNote] = useState<string>("");
  const [attribEventId, setAttribEventId] = useState<string>("");
  const [attribBody, setAttribBody] = useState<string>("");
  const [attribLoading, setAttribLoading] = useState<boolean>(false);
  const [recentEvents, setRecentEvents] = useState<object | null>(null);
  const [probesPayload, setProbesPayload] = useState<object | null>(null);
  const [correlationPayload, setCorrelationPayload] = useState<object | null>(null);
  const [correlationLoading, setCorrelationLoading] = useState<boolean>(false);
  const [livePollEnabled, setLivePollEnabled] = useState<boolean>(true);

  const [previewBody, setPreviewBody] = useState({
    endpoint_id: "",
    failure_event_id: "",
    requested_action: "reset_proxy",
  });

  const fetchJson = useCallback(
    async (path: string, init?: RequestInit) => {
      if (!base) throw new Error("NEXT_PUBLIC_PLATFORM_API not set");
      const r = await fetch(`${base}${path}`, {
        ...init,
        headers: { ...(init?.headers || {}), ...headers },
      });
      if (!r.ok) throw new Error(`${path}: ${r.status} ${await r.text()}`);
      return r.json();
    },
    [headers],
  );

  const load = useCallback(() => {
    if (!base) {
      setError("Set NEXT_PUBLIC_PLATFORM_API (copy frontend/.env.local.example)");
      return;
    }
    setError("");
    const pub = { headers: {} as Record<string, string> };
    Promise.all([
      fetch(`${base}/platform/health`).then((r) => r.json()),
      fetch(`${base}/platform/metrics`).then((r) => r.json()),
      fetch(`${base}/platform/endpoints`, pub).then((r) => r.json()),
      fetch(`${base}/platform/failure-events?limit=80`, pub).then((r) => r.json()),
      fetch(`${base}/platform/policy/summary`)
        .then((r) => (r.ok ? r.json() : {}))
        .catch(() => ({})),
      role === "viewer"
        ? Promise.resolve({ items: [], parse_errors: [] })
        : fetchJson("/platform/events?limit=40").catch(() => ({ items: [], parse_errors: [] })),
      role === "viewer" || role === "operator"
        ? Promise.resolve({ items: [] })
        : fetchJson("/platform/audit?limit=40"),
      fetchJson("/platform/incidents?limit=25"),
      role === "viewer"
        ? Promise.resolve({ items: [] })
        : fetchJson("/platform/events/recent?limit=30").catch(() => ({ items: [] })),
      fetchJson("/platform/probes").catch(() => null),
    ])
      .then(([h, m, ep, ev, pol, nev, au, inc, recent, probes]) => {
        setHealth(h);
        setMetrics(m);
        setEndpoints(ep);
        setFailureEvents(ev);
        setPolicySummary(pol);
        setNormEventsPayload(nev);
        setAudit(au);
        setIncidentsPayload(inc);
        setRecentEvents(recent);
        setProbesPayload(probes);
        try {
          const items = (((ev as { items?: unknown[] }).items || []) as Record<string, unknown>[]).slice(0);
          items.sort((a, b) => String(b.last_seen_at || "").localeCompare(String(a.last_seen_at || "")));
          setTimelineNote(
            items.length === 0
              ? "(no failure events yet — ingest via agent / demo_fleet)"
              : `Showing newest ${Math.min(items.length, 15)} incident candidates by last_seen_at`,
          );
        } catch {
          setTimelineNote("(timeline derive error)");
        }
      })
      .catch((e: unknown) => setError(String(e)));
  }, [base, fetchJson, role]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!base || !livePollEnabled) return;
    const id = window.setInterval(() => {
      if (role === "viewer") return;
      fetchJson("/platform/events/recent?limit=30")
        .then((body) => setRecentEvents(body))
        .catch(() => undefined);
    }, 10000);
    return () => window.clearInterval(id);
  }, [base, fetchJson, livePollEnabled, role]);

  async function runCorrelationProbe() {
    setCorrelationLoading(true);
    setCorrelationPayload(null);
    try {
      const body = await fetchJson("/platform/correlation/run", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({ endpoint_id: "dashboard-local", use_probe: true, requested_action: "inspect_proxy" }),
      });
      setCorrelationPayload(body);
    } catch (e: unknown) {
      setCorrelationPayload({ error: String(e) });
    } finally {
      setCorrelationLoading(false);
    }
  }

  async function postReplayPreview() {
    setReplayOutput("");
    const demo = {
      events: [
        {
          schema_version: "1",
          event_id: "ui-replay-sample",
          event_type: "normalized.remediation_candidate",
          severity: "low",
          endpoint_id_hash: "0".repeat(32),
          signals: { remediation_action: "reset_dns", simulated_operator_role: role },
        },
      ],
    };
    try {
      const body = await fetchJson("/platform/replay/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(demo),
      });
      setReplayOutput(JSON.stringify(body, null, 2));
    } catch (e: unknown) {
      setReplayOutput(String(e));
    }
  }

  async function fetchAttributionSample() {
    setAttribLoading(true);
    setAttribBody("");
    if (role === "viewer") {
      setAttribLoading(false);
      setAttribBody(JSON.stringify({ error: "viewer cannot call /platform/attribution (switch role)" }));
      return;
    }
    if (!attribEventId.trim()) {
      setAttribLoading(false);
      setAttribBody(JSON.stringify({ error: "enter failure_event event_id first" }));
      return;
    }
    try {
      const body = await fetchJson(`/platform/attribution/${encodeURIComponent(attribEventId.trim())}?persist=false`);
      setAttribBody(JSON.stringify(body, null, 2));
    } catch (e: unknown) {
      setAttribBody(JSON.stringify({ error: String(e) }));
    } finally {
      setAttribLoading(false);
    }
  }

  async function postPreview() {
    setPreviewResult("");
    try {
      const body = await fetchJson("/platform/remediation/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({ ...previewBody, surface: "dashboard" }),
      });
      setPreviewResult(JSON.stringify(body, null, 2));
    } catch (e: unknown) {
      setPreviewResult(String(e));
    }
  }

  const m = metrics || {};
  const byCat = (m.events_by_category as Record<string, number>) || {};
  const items = ((failureEvents as { items?: unknown[] })?.items || []) as Record<string, unknown>[];
  const auditItems = ((audit as { items?: unknown[] })?.items || []) as Record<string, unknown>[];

  return (
    <main style={{ padding: "1.25rem", maxWidth: 1040, margin: "0 auto", fontFamily: "system-ui" }}>
      <h1 style={{ marginTop: 0 }}>Endpoint Reliability Platform</h1>
      <p style={{ fontSize: "0.9rem" }}>
        <Link href="/platform/events">Events</Link> · <Link href="/platform/states">States</Link> ·{" "}
        <Link href="/platform/evidence">Evidence</Link> · <Link href="/platform/policies">Policies</Link> ·{" "}
        <Link href="/platform/replay">Replay</Link> · <Link href="/platform/timeline">Timeline</Link>
      </p>

      <div
        style={{
          border: "1px solid #2a4868",
          background: "#0f1729",
          color: "#dff0ff",
          padding: "0.85rem",
          borderRadius: 10,
          marginBottom: "1.25rem",
        }}
      >
        <strong>Privacy / safety banner.</strong> Events use hashed endpoints only (<code>endpoint_id_hash</code>).
        Attribution confidence is heuristic unless proof-tier providers are wired. No external upload by default — no automatic destructive repair — high-risk actions manual/blocked via policy registry + gate.
      </div>

      <p>
        Backend base URL: <code>{base || "(unset — set NEXT_PUBLIC_PLATFORM_API)"}</code>
      </p>

      <label>
        RBAC simulation (stored in browser):{" "}
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="viewer">viewer</option>
          <option value="operator">operator</option>
          <option value="admin">admin</option>
          <option value="security_auditor">security_auditor</option>
        </select>
      </label>
      <p style={{ fontSize: "0.9rem", opacity: 0.85 }}>
        Sends <code>X-Operator-Role</code> / <code>X-Operator-Id</code> with preview / audit fetch. Operators cannot
        read audit; auditors cannot remediate via UI here.
      </p>

      {error ? <p style={{ color: "salmon" }}>{error}</p> : null}
      <p>
        <button type="button" onClick={() => load()}>
          Refresh dashboards
        </button>{" "}
        <label style={{ marginLeft: 12 }}>
          <input
            type="checkbox"
            checked={livePollEnabled}
            onChange={(e) => setLivePollEnabled(e.target.checked)}
          />{" "}
          Live poll events (10s)
        </label>
      </p>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>OS probe (Linux / Debian / Ubuntu / WSL / Windows)</h2>
        <pre style={{ overflow: "auto", maxHeight: 180 }}>
          {probesPayload ? JSON.stringify(probesPayload, null, 2) : "…loading"}
        </pre>
      </section>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>Event correlation & evidence graph</h2>
        <p style={{ fontSize: "0.85rem", opacity: 0.85 }}>
          Runs <code>POST /platform/correlation/run</code> with probe observations — preview-only, append-only audit.
        </p>
        <button type="button" disabled={correlationLoading} onClick={() => runCorrelationProbe()}>
          {correlationLoading ? "Correlating…" : "Run correlation (probe)"}
        </button>
        {correlationPayload ? (
          <>
            <EvidenceTreeView tree={(correlationPayload as { evidence_tree?: unknown }).evidence_tree} />
            <pre style={{ overflow: "auto", maxHeight: 260, marginTop: 10 }}>
              {JSON.stringify(correlationPayload, null, 2)}
            </pre>
          </>
        ) : null}
      </section>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>Real-time event feed</h2>
        <p style={{ fontSize: "0.85rem", opacity: 0.85 }}>
          Merged normalized + failure events from <code>/platform/events/recent</code>.
        </p>
        {(() => {
          const rows = (((recentEvents as { items?: unknown[] }) || {}).items || []) as Record<string, unknown>[];
          if (!rows.length) {
            return <p>{role === "viewer" ? "(viewer — no recent feed)" : "No recent events"}</p>;
          }
          return (
            <table style={{ borderCollapse: "collapse", width: "100%", fontSize: "0.82rem" }}>
              <thead>
                <tr style={{ textAlign: "left" }}>
                  <th style={th}>stream</th>
                  <th style={th}>id</th>
                  <th style={th}>type / category</th>
                  <th style={th}>time</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 20).map((row, idx) => (
                  <tr key={`${String(row.stream)}-${String(row.event_id || idx)}`}>
                    <td style={td}>{String(row.stream ?? "")}</td>
                    <td style={td}>{String(row.event_id ?? row.cluster_id ?? "").slice(0, 18)}</td>
                    <td style={td}>{String(row.event_type ?? row.category ?? "")}</td>
                    <td style={td}>{String(row.timestamp ?? row.last_seen_at ?? "")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          );
        })()}
      </section>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>Platform health</h2>
        <pre style={{ overflow: "auto", maxHeight: 200 }}>{health ? JSON.stringify(health, null, 2) : "…loading"}</pre>
      </section>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>Policy catalog summary</h2>
        <pre style={{ overflow: "auto", maxHeight: 220 }}>
          {policySummary ? JSON.stringify(policySummary, null, 2) : "…loading"}
        </pre>
      </section>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>Incidents (clustered)</h2>
        <p style={{ fontSize: "0.85rem", opacity: 0.85 }}>
          Data from <code>/platform/incidents</code> — deterministic windows over failure-event JSONL.
        </p>
        {(() => {
          const incItems = (((incidentsPayload as { items?: unknown[] }) || {}).items || []) as Record<string, unknown>[];
          if (!incItems.length) {
            return <p>No incident clusters computed yet.</p>;
          }
          return (
            <table style={{ borderCollapse: "collapse", width: "100%", fontSize: "0.82rem" }}>
              <thead>
                <tr style={{ textAlign: "left" }}>
                  <th style={th}>cluster_id</th>
                  <th style={th}>category</th>
                  <th style={th}>severity</th>
                  <th style={th}>events</th>
                  <th style={th}>endpoints</th>
                </tr>
              </thead>
              <tbody>
                {incItems.slice(0, 15).map((row) => (
                  <tr key={String(row.cluster_id)}>
                    <td style={td}>{String(row.cluster_id ?? "").slice(0, 10)}…</td>
                    <td style={td}>{String(row.category ?? "")}</td>
                    <td style={td}>{String(row.cluster_severity ?? "")}</td>
                    <td style={td}>{String(row.event_count ?? "")}</td>
                    <td style={td}>{String(row.affected_endpoint_count ?? "")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          );
        })()}
      </section>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>Failure-event timeline note</h2>
        <p style={{ fontSize: "0.85rem", opacity: 0.82 }}>{timelineNote}</p>
      </section>

      <section style={{ marginTop: "1.5rem" }}>
        <h2>Unified normalized events</h2>
        <p style={{ fontSize: "0.9rem", opacity: 0.85 }}>
          Requires <strong>operator</strong> / <strong>admin</strong> (blocked for viewer). Rows come from{" "}
          <code>normalized_events.jsonl</code>.
        </p>
        {(() => {
          const neItems = (((normEventsPayload as { items?: unknown[] }) || {}).items || []) as Record<string, unknown>[];
          const parseErrs =
            (((normEventsPayload as { parse_errors?: unknown[] }) || {}).parse_errors || []) as Record<string, unknown>[];
          if (!neItems.length) {
            return <p>{role === "viewer" ? "(viewer scope — skipping fetch)" : "No normalized rows yet"}</p>;
          }
          return (
            <>
              {parseErrs.length ? (
                <p style={{ color: "#b45309" }}>Parse issues (tail rows): {parseErrs.length}</p>
              ) : null}
              <table style={{ borderCollapse: "collapse", width: "100%", fontSize: "0.82rem" }}>
                <thead>
                  <tr style={{ textAlign: "left" }}>
                    <th style={th}>event_id</th>
                    <th style={th}>type</th>
                    <th style={th}>severity</th>
                    <th style={th}>endpoint hash</th>
                    <th style={th}>policy • preview/exec</th>
                    <th style={th}>attribution</th>
                  </tr>
                </thead>
                <tbody>
                  {neItems.map((ev) => {
                    const pd = ev.policy_decision as Record<string, unknown> | undefined | null;
                    const aa = ev.actor_attribution as Record<string, unknown> | undefined | null;
                    const rc = pd && Array.isArray(pd.reason_codes) ? (pd.reason_codes as unknown[]).join(", ") : "—";
                    const pe =
                      pd !== undefined && pd !== null
                        ? `prev=${pd.preview_allowed ? "Y" : "N"}exec=${pd.execute_allowed ? "Y" : "N"} • ${rc}`
                        : "(no embedded policy)";
                    const att =
                      aa && aa.confidence
                        ? `${String(aa.confidence)} / ${String(aa.method ?? "n/a")}`
                        : "none";
                    return (
                      <tr key={String(ev.event_id)}>
                        <td style={td}>{String(ev.event_id ?? "")}</td>
                        <td style={td}>{String(ev.event_type ?? "")}</td>
                        <td style={td}>{String(ev.severity ?? "")}</td>
                        <td style={{ ...td, maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {String(ev.endpoint_id_hash ?? "").slice(0, 22)}…
                        </td>
                        <td style={td}>{pe}</td>
                        <td style={td}>{att}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </>
          );
        })()}
      </section>

      <h2 style={{ marginTop: "1.75rem" }}>Key counters</h2>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
          gap: "0.65rem",
        }}
      >
        <Tile label="Endpoints" value={m.endpoint_count} />
        <Tile label="Open failure events" value={m.open_failure_events} />
        <Tile label="Incident clusters" value={m.incident_cluster_count} />
        <Tile label="Affected endpoints (clusters)" value={m.affected_endpoint_count} />
        <Tile label="Blocked actions (audit)" value={m.blocked_action_count} />
        <Tile label="Dry-run executes" value={m.dry_run_execution_count} />
        <Tile label="Repair success rate" value={m.repair_success_rate ?? "n/a"} />
        <Tile label="False positive rate" value={m.false_positive_rate ?? "n/a"} />
      </div>

      <h2 style={{ marginTop: "1.75rem" }}>Failure counts by category</h2>
      <table style={{ borderCollapse: "collapse", width: "100%", maxWidth: 480 }}>
        <thead>
          <tr style={{ textAlign: "left" }}>
            <th style={th}>Category</th>
            <th style={th}>Count</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(byCat).length === 0 ? (
            <tr>
              <td colSpan={2} style={td}>
                — no events yet —
              </td>
            </tr>
          ) : (
            Object.entries(byCat).map(([k, v]) => (
              <tr key={k}>
                <td style={td}>{k}</td>
                <td style={td}>{v}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      <h2 style={{ marginTop: "1.75rem" }}>Recent failure events</h2>
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: "0.9rem" }}>
        <thead>
          <tr style={{ textAlign: "left" }}>
            <th style={th}>event_id</th>
            <th style={th}>endpoint</th>
            <th style={th}>category</th>
            <th style={th}>severity</th>
          </tr>
        </thead>
        <tbody>
          {items.slice(0, 12).map((ev) => (
            <tr key={String(ev.event_id)}>
              <td style={td}>{String(ev.event_id)}</td>
              <td style={td}>{String(ev.endpoint_id)}</td>
              <td style={td}>{String(ev.category)}</td>
              <td style={td}>{String(ev.severity)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 style={{ marginTop: "1.75rem" }}>Replay preview (dry, local)</h2>
      <p style={{ fontSize: "0.9rem", opacity: 0.85 }}>
        Posts a deterministic inline event bundle to <code>/platform/replay/preview</code> — recomputes policy gates only.
      </p>
      <button type="button" onClick={() => postReplayPreview()}>
        Run replay preview sample
      </button>
      {replayOutput ? <pre style={{ overflow: "auto", maxHeight: 220 }}>{replayOutput}</pre> : null}

      <h2 style={{ marginTop: "1.75rem" }}>Attribution drill-down</h2>
      <p style={{ fontSize: "0.9rem", opacity: 0.86 }}>
        Operator / admin / security roles only — calls <code>GET /platform/attribution/&lt;event_id&gt;?persist=false</code>.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, maxWidth: 520 }}>
        <input
          placeholder="failure event_id"
          value={attribEventId}
          onChange={(e) => setAttribEventId(e.target.value)}
        />
        <button type="button" disabled={attribLoading} onClick={() => fetchAttributionSample()}>
          {attribLoading ? "Loading…" : "Fetch attribution JSON"}
        </button>
      </div>
      {attribBody ? <pre style={{ overflow: "auto", maxHeight: 280, marginTop: 10 }}>{attribBody}</pre> : null}

      <h2 style={{ marginTop: "1.75rem" }}>Remediation preview (demo)</h2>
      <p style={{ fontSize: "0.9rem" }}>
        Requires <strong>operator</strong> or <strong>admin</strong>. Paste ids from the table above.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, maxWidth: 420 }}>
        <input
          placeholder="endpoint_id"
          value={previewBody.endpoint_id}
          onChange={(e) => setPreviewBody((b) => ({ ...b, endpoint_id: e.target.value }))}
        />
        <input
          placeholder="failure_event_id"
          value={previewBody.failure_event_id}
          onChange={(e) => setPreviewBody((b) => ({ ...b, failure_event_id: e.target.value }))}
        />
        <select
          value={previewBody.requested_action}
          onChange={(e) => setPreviewBody((b) => ({ ...b, requested_action: e.target.value }))}
        >
          <option value="reset_proxy">reset_proxy</option>
          <option value="reset_dns">reset_dns</option>
          <option value="reset_firewall">reset_firewall (expect policy block preview)</option>
          <option value="inspect_proxy">inspect_proxy</option>
        </select>
        <button type="button" onClick={() => postPreview()}>
          Request preview
        </button>
      </div>
      {previewResult ? (
        <pre style={{ overflow: "auto", maxHeight: 280, marginTop: 10 }}>{previewResult}</pre>
      ) : null}

      <h2 style={{ marginTop: "1.75rem" }}>Audit log (admin / security_auditor)</h2>
      {role === "viewer" || role === "operator" ? (
        <p style={{ opacity: 0.8 }}>Switch role to admin or security_auditor to fetch audit rows.</p>
      ) : (
        <table style={{ borderCollapse: "collapse", width: "100%", fontSize: "0.85rem" }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th style={th}>timestamp</th>
              <th style={th}>action</th>
              <th style={th}>actor</th>
              <th style={th}>decision</th>
            </tr>
          </thead>
          <tbody>
            {auditItems.slice(0, 15).map((a) => (
              <tr key={String(a.audit_id || a.timestamp)}>
                <td style={td}>{String(a.timestamp)}</td>
                <td style={td}>{String(a.action)}</td>
                <td style={td}>{String(a.actor)}</td>
                <td style={td}>{String(a.decision)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p style={{ marginTop: "2rem" }}>
        <Link href="/">← Home</Link>
      </p>
    </main>
  );
}

function EvidenceTreeView(props: { tree: unknown }) {
  const tree = props.tree as Record<string, unknown> | null | undefined;
  if (!tree) return null;
  const root = tree.root as Record<string, unknown> | undefined;
  const rejected = (tree.rejected_alternatives as unknown[]) || [];
  return (
    <div
      style={{
        marginTop: 12,
        padding: 12,
        border: "1px solid #334155",
        borderRadius: 8,
        background: "#0b1220",
        color: "#e2e8f0",
        fontSize: "0.85rem",
      }}
    >
      <div>
        <strong>Accepted:</strong> {String(tree.accepted_hypothesis ?? "—")}
      </div>
      <div>
        <strong>State path:</strong> {((tree.state_path as string[]) || []).join(" → ") || "—"}
      </div>
      {root ? (
        <div style={{ marginTop: 8 }}>
          <strong>Root evidence:</strong> {String(root.label ?? root.kind ?? JSON.stringify(root).slice(0, 120))}
        </div>
      ) : null}
      {rejected.length ? (
        <div style={{ marginTop: 8 }}>
          <strong>Rejected alternatives:</strong> {rejected.length}
        </div>
      ) : null}
    </div>
  );
}

function Tile(props: { label: string; value: unknown }) {
  return (
    <div style={{ border: "1px solid #ccc", borderRadius: 8, padding: "0.65rem", background: "#fafafa" }}>
      <div style={{ fontSize: "0.8rem", color: "#555" }}>{props.label}</div>
      <div style={{ fontWeight: 600, fontSize: "1.2rem" }}>{String(props.value ?? "—")}</div>
    </div>
  );
}

const th = { padding: "6px 8px", borderBottom: "1px solid #ccc" } as const;
const td = { padding: "6px 8px", borderBottom: "1px solid #eee" } as const;
