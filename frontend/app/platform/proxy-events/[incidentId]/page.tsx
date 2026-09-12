"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PlatformShell, platformFetch } from "../../../../components/PlatformShell";

export default function ProxyIncidentDetailPage() {
  const params = useParams();
  const incidentId = String(params.incidentId || "");
  const [bundle, setBundle] = useState<Record<string, unknown> | null>(null);
  const [timeline, setTimeline] = useState<unknown[]>([]);
  const [tree, setTree] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    if (!incidentId) return;
    Promise.all([
      platformFetch(`/api/proxy/incidents/${incidentId}`).then((r) => r.json()),
      platformFetch(`/api/proxy/incidents/${incidentId}/timeline`).then((r) => r.json()),
      platformFetch(`/api/proxy/incidents/${incidentId}/evidence-tree`).then((r) => r.json()),
    ]).then(([b, tl, et]) => {
      setBundle(b);
      setTimeline(tl.events || []);
      setTree(et.evidence_tree || null);
    });
  }, [incidentId]);

  const policy = (bundle?.policy || {}) as Record<string, unknown>;
  const causation = (bundle?.causation || {}) as Record<string, unknown>;

  return (
    <PlatformShell title={`Incident ${incidentId}`} active="/platform/proxy-events">
      {!bundle ? <p>Loading…</p> : null}
      {bundle ? (
        <>
          <section style={{ marginBottom: 16 }}>
            <h2>Causation</h2>
            <p>
              Level: <strong>{String(causation.causation_level)}</strong> — {String(causation.explanation)}
            </p>
            <p>Writer: {String(causation.writer_process)}</p>
            <p>Command line: {String(causation.writer_command_line || "n/a")}</p>
            <p>Parent: {String(causation.parent_process)} — {String(causation.parent_command_line || "")}</p>
          </section>
          <section style={{ marginBottom: 16 }}>
            <h2>Policy</h2>
            <p>
              {String(policy.decision)} / {String(policy.severity)}
            </p>
            <ul>
              {((policy.explanation as string[]) || []).map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
            <p style={{ fontSize: "0.85rem", opacity: 0.85 }}>
              Preview-only remediation — no one-click kill. Use typed confirmation for proxy-disable.
            </p>
          </section>
          <section style={{ marginBottom: 16 }}>
            <h2>Timeline</h2>
            <pre style={{ fontSize: "0.8rem", overflow: "auto" }}>{JSON.stringify(timeline, null, 2)}</pre>
          </section>
          <section>
            <h2>Evidence tree</h2>
            <pre style={{ fontSize: "0.8rem", overflow: "auto" }}>{JSON.stringify(tree, null, 2)}</pre>
          </section>
        </>
      ) : null}
    </PlatformShell>
  );
}
