"use client";

import { useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

const SAMPLE_OBS = [
  { source_kind: "registry", signal_name: "wininet_proxy_enabled", signal_value: 1 },
  { source_kind: "network_telemetry", signal_name: "localhost_proxy_detected", signal_value: "127.0.0.1:61187" },
  { source_kind: "network_telemetry", signal_name: "browser_https_failed" },
];

export default function PlatformStatesPage() {
  const [result, setResult] = useState<string>("");
  const [loading, setLoading] = useState(false);

  async function runTransition() {
    setLoading(true);
    setResult("");
    try {
      const r = await platformFetch("/platform/v2/decisions/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpoint_id: "ui-states", observations: SAMPLE_OBS }),
      });
      const body = await r.json();
      setResult(JSON.stringify({ state_path: body.state_path, policy_outcome: body.policy_outcome }, null, 2));
    } catch (e: unknown) {
      setResult(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <PlatformShell
      title="State Machine"
      subtitle="Deterministic transitions: NORMAL → LOCAL_PROXY_ENABLED → PROXY_FAILURE → …"
      active="/platform/states"
    >
      <p style={{ fontSize: "0.88rem" }}>
        Runs the v2 decision pipeline on a sample proxy-drift bundle and shows the canonical state path.
      </p>
      <button type="button" disabled={loading} onClick={() => runTransition()}>
        {loading ? "Running…" : "Compute state path (sample)"}
      </button>
      {result ? <pre style={{ marginTop: 12, overflow: "auto", maxHeight: 320 }}>{result}</pre> : null}
    </PlatformShell>
  );
}
