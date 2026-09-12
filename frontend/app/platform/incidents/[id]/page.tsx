"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PlatformShell, platformFetch } from "../../../../components/PlatformShell";

export default function PlatformIncidentDetailPage() {
  const params = useParams();
  const incidentId = String(params.id || "");
  const [row, setRow] = useState<Record<string, unknown> | null>(null);
  const [slo, setSlo] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    if (!incidentId) return;
    Promise.all([
      platformFetch(`/platform/incidents/${encodeURIComponent(incidentId)}`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      platformFetch("/platform/slo").then((r) => r.json()),
    ]).then(([inc, sloBody]) => {
      setRow(inc);
      setSlo(sloBody);
    });
  }, [incidentId]);

  return (
    <PlatformShell title={`Incident ${incidentId}`} active="/platform/incidents">
      {!row ? (
        <p>
          Incident not in platform store — see case study{" "}
          <code>case_studies/{incidentId}/</code> or run <code>incident-review --incident-id {incidentId}</code>.
        </p>
      ) : (
        <>
          <p>
            <strong>Status:</strong> {String(row.state || row.status)} · <strong>Severity:</strong>{" "}
            {String(row.severity)}
          </p>
          <p>
            <strong>Evidence level:</strong> {String(row.evidence_level || "observation")} ·{" "}
            <strong>Policy gate:</strong> {String(row.policy_gate || "preview")}
          </p>
          <p>
            <strong>Proof status:</strong> {String(row.proof_status || "unavailable")}
          </p>
          <h2>Timeline</h2>
          <pre style={{ fontSize: "0.82rem", overflow: "auto" }}>{JSON.stringify(row.timeline || row.events || [], null, 2)}</pre>
          <h2>Limitations</h2>
          <ul>
            <li>Observation ≠ proof — registry writer claims need Sysmon/Procmon-class telemetry.</li>
            <li>Policy PREVIEW ≠ autonomous remediation approval.</li>
          </ul>
          <h2>Recommended next actions</h2>
          <ul>
            <li>python -m src proxy-causation --fixture tests/fixtures/proxy_causation/scenario1_proven_writer_port_owner</li>
            <li>python -m src incident-review --incident-id {incidentId}</li>
          </ul>
        </>
      )}
      {slo ? (
        <section style={{ marginTop: 24 }}>
          <h2>Platform SLO snapshot</h2>
          <pre style={{ fontSize: "0.82rem" }}>{JSON.stringify(slo, null, 2)}</pre>
        </section>
      ) : null}
    </PlatformShell>
  );
}
