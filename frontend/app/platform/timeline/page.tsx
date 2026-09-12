"use client";

import { useCallback, useEffect, useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

export default function PlatformTimelinePage() {
  const [v2Events, setV2Events] = useState<Record<string, unknown>[]>([]);
  const [failureEvents, setFailureEvents] = useState<Record<string, unknown>[]>([]);

  const load = useCallback(async () => {
    const [ev, fe] = await Promise.all([
      platformFetch("/platform/v2/events?limit=40")
        .then((r) => r.json())
        .catch(() => ({ items: [] })),
      platformFetch("/platform/failure-events?limit=40", { role: "viewer" })
        .then((r) => r.json())
        .catch(() => ({ items: [] })),
    ]);
    setV2Events((ev.items as Record<string, unknown>[]) || []);
    setFailureEvents((fe.items as Record<string, unknown>[]) || []);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  type Row = { stream: string; id: string; label: string; time: string };
  const merged: Row[] = [
    ...v2Events.map((e) => ({
      stream: "v2_normalized",
      id: String(e.event_id || ""),
      label: String(e.signal_name || ""),
      time: String(e.timestamp_utc || ""),
    })),
    ...failureEvents.map((e) => ({
      stream: "failure_event",
      id: String(e.event_id || ""),
      label: String(e.category || ""),
      time: String(e.last_seen_at || e.first_seen_at || ""),
    })),
  ].sort((a, b) => b.time.localeCompare(a.time));

  return (
    <PlatformShell
      title="Timeline"
      subtitle="Merged chronological view of v2 normalized events and legacy failure events."
      active="/platform/timeline"
    >
      <button type="button" onClick={() => load()}>
        Refresh timeline
      </button>
      <table style={{ width: "100%", marginTop: 12, borderCollapse: "collapse", fontSize: "0.85rem" }}>
        <thead>
          <tr>
            <th style={th}>stream</th>
            <th style={th}>id</th>
            <th style={th}>label</th>
            <th style={th}>time</th>
          </tr>
        </thead>
        <tbody>
          {merged.slice(0, 50).map((row) => (
            <tr key={`${row.stream}-${row.id}`}>
              <td style={td}>{row.stream}</td>
              <td style={td}>{row.id.slice(0, 16)}</td>
              <td style={td}>{row.label}</td>
              <td style={td}>{row.time}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </PlatformShell>
  );
}

const th = { textAlign: "left" as const, padding: "6px 8px", borderBottom: "1px solid #ccc" };
const td = { padding: "6px 8px", borderBottom: "1px solid #eee" };
