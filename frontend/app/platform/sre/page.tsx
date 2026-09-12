"use client";

import { useCallback, useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

export default function PlatformSREPage() {
  const [incidents, setIncidents] = useState<Record<string, unknown>[]>([]);
  const [mttr, setMttr] = useState<Record<string, unknown> | null>(null);
  const [output, setOutput] = useState("");

  const load = useCallback(async () => {
    const [inc, m] = await Promise.all([
      platformFetch("/platform/v2/sre/incidents").then((r) => r.json()),
      platformFetch("/platform/v2/sre/metrics/mttr").then((r) => r.json()),
    ]);
    setIncidents((inc.items as Record<string, unknown>[]) || []);
    setMttr(m.metrics as Record<string, unknown>);
  }, []);

  async function openIncident() {
    const r = await platformFetch("/platform/v2/sre/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoint_id: "ui-sre",
        title: "UI-opened incident",
        severity: "medium",
      }),
    });
    setOutput(JSON.stringify(await r.json(), null, 2));
    load();
  }

  return (
    <PlatformShell
      title="SRE Incidents"
      subtitle="Event-sourced incidents, lifecycle MTTR, timeline reconstruction, postmortems."
      active="/platform/sre"
    >
      <button type="button" onClick={() => load()}>
        Refresh
      </button>{" "}
      <button type="button" onClick={() => openIncident()}>
        Open incident (sample)
      </button>
      {mttr ? (
        <p style={{ fontSize: "0.88rem", marginTop: 12 }}>
          Incidents: {String(mttr.incident_count)} · Resolved: {String(mttr.resolved_count)} · MTTR (mean):{" "}
          {String(mttr.mean_time_to_recover_seconds ?? "n/a")}s
        </p>
      ) : null}
      <table style={{ width: "100%", marginTop: 12, borderCollapse: "collapse", fontSize: "0.85rem" }}>
        <thead>
          <tr>
            <th style={th}>incident_id</th>
            <th style={th}>phase</th>
            <th style={th}>severity</th>
            <th style={th}>endpoint</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((row) => (
            <tr key={String(row.incident_id)}>
              <td style={td}>{String(row.incident_id).slice(0, 16)}…</td>
              <td style={td}>{String(row.phase)}</td>
              <td style={td}>{String(row.severity)}</td>
              <td style={td}>{String(row.endpoint_id)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {output ? <pre style={{ marginTop: 12, maxHeight: 200, overflow: "auto" }}>{output}</pre> : null}
    </PlatformShell>
  );
}

const th = { textAlign: "left" as const, padding: "6px 8px", borderBottom: "1px solid #ccc" };
const td = { padding: "6px 8px", borderBottom: "1px solid #eee" };
