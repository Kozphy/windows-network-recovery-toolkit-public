"use client";

import { useEffect, useState } from "react";
import { PlatformShell } from "../../../components/PlatformShell";
import { triskFetch } from "../../../lib/trisk-api";

export default function AuditViewerPage() {
  const [verify, setVerify] = useState<Record<string, unknown> | null>(null);
  const [report, setReport] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([triskFetch("/v1/audit/verify"), triskFetch("/v1/reports/executive")])
      .then(([v, r]) => {
        setVerify(v);
        setReport(r);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <PlatformShell title="Audit Viewer" subtitle="Hash chain verify + executive report" active="/platform/audit-viewer">
      {error ? <p style={{ color: "crimson" }}>{error}</p> : null}
      <section>
        <h2>Audit verify</h2>
        <pre style={{ fontSize: "0.8rem" }}>{JSON.stringify(verify, null, 2)}</pre>
      </section>
      <section>
        <h2>Governance report (snippet)</h2>
        <pre style={{ fontSize: "0.75rem", overflow: "auto", maxHeight: "40vh" }}>
          {JSON.stringify(report, null, 2)}
        </pre>
      </section>
    </PlatformShell>
  );
}
