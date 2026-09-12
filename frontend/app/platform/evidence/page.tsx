"use client";

import { useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

export default function PlatformEvidencePage() {
  const [graph, setGraph] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  async function loadGraph() {
    setLoading(true);
    try {
      const r = await platformFetch("/platform/v2/decisions/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          endpoint_id: "ui-evidence",
          observations: [
            { source_kind: "sysmon", signal_name: "registry_write_proxyenable", evidence_tier: "TIER_3_CAUSAL_PROOF" },
            { source_kind: "network_telemetry", signal_name: "localhost_proxy_detected" },
            { source_kind: "registry", signal_name: "wininet_proxy_enabled", signal_value: 1 },
          ],
          context: { process_snapshot: { process_name: "node.exe", parent_name: "powershell.exe" } },
        }),
      });
      const body = await r.json();
      setGraph((body.evidence_graph_summary as Record<string, unknown>) || null);
    } finally {
      setLoading(false);
    }
  }

  const nodes = ((graph?.nodes as unknown[]) || []) as Record<string, unknown>[];
  const edges = ((graph?.edges as unknown[]) || []) as Record<string, unknown>[];

  return (
    <PlatformShell
      title="Evidence Graph"
      subtitle="Process, registry write, listener, network flow, and policy decision nodes for causal reasoning."
      active="/platform/evidence"
    >
      <button type="button" disabled={loading} onClick={() => loadGraph()}>
        {loading ? "Building…" : "Build evidence graph (sample)"}
      </button>
      {graph ? (
        <>
          <p style={{ marginTop: 12, fontSize: "0.88rem" }}>
            {nodes.length} nodes · {edges.length} edges
          </p>
          <pre style={{ overflow: "auto", maxHeight: 420, fontSize: "0.82rem" }}>
            {JSON.stringify(graph, null, 2)}
          </pre>
        </>
      ) : null}
    </PlatformShell>
  );
}
