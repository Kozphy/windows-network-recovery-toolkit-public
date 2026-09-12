"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

type IncidentRow = Record<string, unknown>;

export default function PlatformIncidentsPage() {
  const [items, setItems] = useState<IncidentRow[]>([]);
  const [clusters, setClusters] = useState<IncidentRow[]>([]);

  useEffect(() => {
    platformFetch("/platform/incidents?limit=50")
      .then((r) => r.json())
      .then((body) => {
        setItems((body.items as IncidentRow[]) || []);
        setClusters((body.clusters as IncidentRow[]) || []);
      });
  }, []);

  return (
    <PlatformShell
      title="Incidents"
      subtitle="Lifecycle incidents and failure-event clusters — preview-only remediation"
      active="/platform/incidents"
    >
      <section style={{ marginBottom: 24 }}>
        <h2>Lifecycle incidents</h2>
        {items.length === 0 ? <p>No lifecycle rows yet — run demo-production or ingest failure events.</p> : null}
        <ul>
          {items.map((row) => {
            const id = String(row.incident_id || row.id || "");
            return (
              <li key={id}>
                <Link href={`/platform/incidents/${encodeURIComponent(id)}`}>{id}</Link>
                {" — "}
                {String(row.state || row.status || "unknown")} / {String(row.severity || "n/a")}
              </li>
            );
          })}
        </ul>
      </section>
      <section>
        <h2>Failure clusters</h2>
        <ul>
          {clusters.map((row, i) => (
            <li key={String(row.cluster_id || i)}>
              {String(row.title || row.category || "cluster")} — endpoints:{" "}
              {String((row.endpoint_ids as string[])?.length ?? 0)}
            </li>
          ))}
        </ul>
      </section>
    </PlatformShell>
  );
}
