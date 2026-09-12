"use client";

import { useEffect, useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

export default function PlatformSloPage() {
  const [slo, setSlo] = useState<Record<string, unknown> | null>(null);
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    Promise.all([
      platformFetch("/platform/slo").then((r) => r.json()),
      platformFetch("/platform/metrics").then((r) => r.json()),
    ]).then(([sloBody, metricsBody]) => {
      setSlo(sloBody);
      setMetrics(metricsBody);
    });
  }, []);

  const rel = (slo?.reliability || {}) as Record<string, unknown>;
  const metricEntries = metrics
    ? Object.entries(metrics as Record<string, unknown>).filter(
        ([k]) =>
          k.startsWith("evidence_level_total_") ||
          k.startsWith("policy_decisions_total_") ||
          k === "audit_replay_success_total" ||
          k === "diagnosis_duration_seconds"
      )
    : [];

  return (
    <PlatformShell
      title="SLO & reliability"
      subtitle="JSONL-derived KPIs — local-first, no cloud upload"
      active="/platform/slo"
    >
      {!slo ? <p>Loading…</p> : (
        <table style={{ borderCollapse: "collapse", fontSize: "0.9rem" }}>
          <tbody>
            {(
              [
                ["Mean time to detect (s)", slo.mean_time_to_detect_seconds],
                ["Mean time to explain (s)", slo.mean_time_to_explain_seconds],
                ["Proxy drift incidents", slo.proxy_drift_incidents_total],
                ["Blocked high-risk actions", slo.blocked_high_risk_action_count],
                ["Remediation previews", slo.remediation_preview_count],
                ["Proof unavailable rate", slo.proof_unavailable_rate],
                ["Final causation rate", slo.final_causation_rate],
                ["Browser path success", rel.browser_path_success_rate],
                ["Remediation stickiness", rel.remediation_stickiness_rate],
              ] as [string, unknown][]
            ).map(([label, val]) => (
              <tr key={label}>
                <td style={{ padding: "6px 12px 6px 0", fontWeight: 600 }}>{label}</td>
                <td>{String(val ?? "—")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {metricEntries.length > 0 ? (
        <section style={{ marginTop: 24 }}>
          <h3 style={{ fontSize: "1rem", marginBottom: 8 }}>Evidence & policy distribution</h3>
          <table style={{ borderCollapse: "collapse", fontSize: "0.85rem" }}>
            <tbody>
              {metricEntries.map(([k, v]) => (
                <tr key={k}>
                  <td style={{ padding: "4px 12px 4px 0", fontWeight: 600 }}>{k}</td>
                  <td>{String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
      {metrics ? (
        <details style={{ marginTop: 24 }}>
          <summary>Raw /platform/metrics</summary>
          <pre style={{ fontSize: "0.78rem", overflow: "auto", maxHeight: 360 }}>
            {JSON.stringify(metrics, null, 2)}
          </pre>
        </details>
      ) : null}
    </PlatformShell>
  );
}
