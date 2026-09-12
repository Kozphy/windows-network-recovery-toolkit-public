"use client";

import { useEffect, useState } from "react";
import { PlatformShell } from "../../../components/PlatformShell";
import { triskFetch } from "../../../lib/trisk-api";

export default function RiskOverviewPage() {
  const [incidents, setIncidents] = useState<{ items: unknown[] } | null>(null);
  const [risks, setRisks] = useState<{ items: unknown[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([triskFetch("/v1/incidents?limit=20"), triskFetch("/v1/risks")])
      .then(([inc, risk]) => {
        setIncidents(inc);
        setRisks(risk);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <PlatformShell title="Risk Overview" subtitle="/v1 incidents and risk scores" active="/platform/risk-overview">
      {error ? <p style={{ color: "crimson" }}>{error}</p> : null}
      <section>
        <h2>Incidents</h2>
        <pre style={{ fontSize: "0.8rem", overflow: "auto" }}>{JSON.stringify(incidents, null, 2)}</pre>
      </section>
      <section>
        <h2>Risk scores</h2>
        <pre style={{ fontSize: "0.8rem", overflow: "auto" }}>{JSON.stringify(risks, null, 2)}</pre>
      </section>
    </PlatformShell>
  );
}
