"use client";

import { useCallback, useEffect, useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

export default function PlatformEventsPage() {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await platformFetch("/platform/v2/events?limit=80");
      if (!r.ok) throw new Error(await r.text());
      const body = await r.json();
      setItems((body.items as Record<string, unknown>[]) || []);
      setError("");
    } catch (e: unknown) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <PlatformShell
      title="Events"
      subtitle="Append-only normalized events from registry, Sysmon, ETW, Event Log, and network telemetry."
      active="/platform/events"
    >
      {error ? <p style={{ color: "salmon" }}>{error}</p> : null}
      <button type="button" onClick={() => load()}>
        Refresh
      </button>
      <table style={{ width: "100%", marginTop: 12, borderCollapse: "collapse", fontSize: "0.85rem" }}>
        <thead>
          <tr>
            <th style={th}>event_id</th>
            <th style={th}>source</th>
            <th style={th}>signal</th>
            <th style={th}>tier</th>
            <th style={th}>time</th>
          </tr>
        </thead>
        <tbody>
          {items.length === 0 ? (
            <tr>
              <td colSpan={5} style={td}>
                No v2 events yet — ingest via POST /platform/v2/events/ingest
              </td>
            </tr>
          ) : (
            items.map((row) => (
              <tr key={String(row.event_id)}>
                <td style={td}>{String(row.event_id).slice(0, 14)}…</td>
                <td style={td}>{String(row.source_kind)}</td>
                <td style={td}>{String(row.signal_name)}</td>
                <td style={td}>{String(row.evidence_tier)}</td>
                <td style={td}>{String(row.timestamp_utc)}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </PlatformShell>
  );
}

const th = { textAlign: "left" as const, padding: "6px 8px", borderBottom: "1px solid #ccc" };
const td = { padding: "6px 8px", borderBottom: "1px solid #eee" };
