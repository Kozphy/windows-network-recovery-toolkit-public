"use client";

import { useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

export default function PlatformReplayPage() {
  const [runId, setRunId] = useState("");
  const [output, setOutput] = useState("");
  const [lastRunId, setLastRunId] = useState("");

  async function createRun() {
    setOutput("");
    const r = await platformFetch("/platform/v2/decisions/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoint_id: "ui-replay",
        observations: [
          { source_kind: "registry", signal_name: "wininet_proxy_enabled", signal_value: 1 },
          { source_kind: "network_telemetry", signal_name: "localhost_proxy_detected" },
        ],
      }),
    });
    const body = await r.json();
    const id = String(body.run_id || "");
    setRunId(id);
    setLastRunId(id);
    setOutput(JSON.stringify({ created_run_id: id, policy_outcome: body.policy_outcome }, null, 2));
  }

  async function replay() {
    if (!runId.trim()) return;
    setOutput("");
    const r = await platformFetch(`/platform/v2/decisions/replay/${encodeURIComponent(runId.trim())}`);
    const body = await r.json();
    setOutput(JSON.stringify(body, null, 2));
  }

  return (
    <PlatformShell
      title="Replay"
      subtitle="Time-travel debugging — reconstruct state, evidence, and decisions from historical events."
      active="/platform/replay"
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 8, maxWidth: 480 }}>
        <button type="button" onClick={() => createRun()}>
          Create sample decision run
        </button>
        {lastRunId ? <p style={{ fontSize: "0.85rem" }}>Last run_id: <code>{lastRunId}</code></p> : null}
        <input placeholder="run_id" value={runId} onChange={(e) => setRunId(e.target.value)} />
        <button type="button" onClick={() => replay()}>
          Replay decision
        </button>
      </div>
      {output ? <pre style={{ marginTop: 12, overflow: "auto", maxHeight: 400 }}>{output}</pre> : null}
    </PlatformShell>
  );
}
