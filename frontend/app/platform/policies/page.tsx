"use client";

import { useCallback, useEffect, useState } from "react";
import { PlatformShell, platformFetch } from "../../../components/PlatformShell";

export default function PlatformPoliciesPage() {
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await platformFetch("/platform/v2/policies/summary");
      if (!r.ok) throw new Error(await r.text());
      setSummary(await r.json());
      setError("");
    } catch (e: unknown) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const rules = ((summary?.rules as unknown[]) || []) as Record<string, unknown>[];

  return (
    <PlatformShell
      title="Policies"
      subtitle="Configurable ALLOW / PREVIEW / BLOCK — default PREVIEW in safe mode."
      active="/platform/policies"
    >
      {error ? <p style={{ color: "salmon" }}>{error}</p> : null}
      <button type="button" onClick={() => load()}>
        Refresh
      </button>
      {summary ? (
        <div style={{ marginTop: 12 }}>
          <p>
            <strong>safe_mode:</strong> {String(summary.safe_mode)} · <strong>default:</strong>{" "}
            {String(summary.default_outcome)}
          </p>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
            <thead>
              <tr>
                <th style={th}>rule_id</th>
                <th style={th}>outcome</th>
                <th style={th}>min_confidence</th>
                <th style={th}>requires_proof</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={String(r.rule_id)}>
                  <td style={td}>{String(r.rule_id)}</td>
                  <td style={td}>{String(r.outcome)}</td>
                  <td style={td}>{String(r.min_confidence ?? "—")}</td>
                  <td style={td}>{String(r.requires_proof_tier ?? false)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </PlatformShell>
  );
}

const th = { textAlign: "left" as const, padding: "6px 8px", borderBottom: "1px solid #ccc" };
const td = { padding: "6px 8px", borderBottom: "1px solid #eee" };
