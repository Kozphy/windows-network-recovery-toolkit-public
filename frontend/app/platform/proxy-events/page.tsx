"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

type IncidentCard = {
  incident_id: string;
  timestamp_utc?: string;
  risk?: string;
  causation_level?: string;
  registry_writer?: string;
  classification?: string;
  policy_decision?: string;
  policy_severity?: string;
  proxy_before?: Record<string, unknown>;
  proxy_after?: Record<string, unknown>;
  localhost_port?: number;
  status?: string;
};

export default function ProxyEventsPage() {
  const [incidents, setIncidents] = useState<IncidentCard[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    platformFetch("/api/proxy/incidents")
      .then((r) => r.json())
      .then((d) => setIncidents(d.incidents || []))
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <PlatformShell title="Proxy incidents" subtitle="Causation · classification · policy" active="/platform/proxy-events">
      {error ? <p style={{ color: "salmon" }}>{error}</p> : null}
      <div style={{ display: "grid", gap: 12 }}>
        {incidents.map((inc) => (
          <Link
            key={inc.incident_id}
            href={`/platform/proxy-events/${inc.incident_id}`}
            style={{
              display: "block",
              padding: 12,
              border: "1px solid #ddd",
              borderRadius: 8,
              textDecoration: "none",
              color: "inherit",
            }}
          >
            <strong>{inc.incident_id}</strong> — {inc.timestamp_utc}
            <div style={{ fontSize: "0.85rem", marginTop: 6 }}>
              Status: {inc.status} · Causation: {inc.causation_level} · Class: {inc.classification}
            </div>
            <div style={{ fontSize: "0.85rem" }}>
              Policy: {inc.policy_decision} ({inc.policy_severity}) · Writer: {inc.registry_writer || "n/a"}
            </div>
            <div style={{ fontSize: "0.82rem", opacity: 0.8 }}>
              Proxy: {String(inc.proxy_before?.proxy_server ?? "null")} → {String(inc.proxy_after?.proxy_server ?? "null")}
              {inc.localhost_port ? ` · port ${inc.localhost_port}` : ""}
            </div>
          </Link>
        ))}
      </div>
    </PlatformShell>
  );
}
