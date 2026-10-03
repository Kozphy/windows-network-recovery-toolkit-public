"use client";

import { useEffect, useMemo, useState } from "react";
import { Line } from "react-chartjs-2";
import { CategoryScale, Chart as ChartJS, Legend, LinearScale, LineElement, PointElement, Tooltip } from "chart.js";
import { authFetch } from "../../lib/api";
import { supabase } from "../../lib/supabase";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

const nav = ["Overview", "Endpoints", "Risk", "Recovery", "Audit"];

function Stat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="metric-card"><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

export default function DashboardPage() {
  const [token, setToken] = useState("");
  const [history, setHistory] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => { supabase.auth.getSession().then(({ data }) => setToken(data.session?.access_token || "")); }, []);
  useEffect(() => {
    if (!token) return;
    authFetch("/history?limit=50", token).then(setHistory).catch((err) => setError(String(err)));
  }, [token]);

  const metrics = history?.connection_metrics || [];
  const diagnosis = history?.diagnosis_logs || [];
  const lastDiagnosis = diagnosis[0];
  const anomaly = lastDiagnosis?.result?.anomaly;
  const unhealthy = diagnosis.filter((d: any) => d?.result?.risk && String(d.result.risk).toLowerCase() !== "low").length;

  const chartData = useMemo(() => ({
    labels: metrics.slice().reverse().map((m: any) => new Date(m.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })),
    datasets: [
      { label: "TIME_WAIT", data: metrics.slice().reverse().map((m: any) => m.time_wait), borderColor: "#f97316", backgroundColor: "#f97316", tension: 0.35 },
      { label: "ESTABLISHED", data: metrics.slice().reverse().map((m: any) => m.established), borderColor: "#2563eb", backgroundColor: "#2563eb", tension: 0.35 },
    ],
  }), [metrics]);

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">W</span><div><b>WNRT</b><small>Risk Operations</small></div></div>
      <nav>{nav.map((item, i) => <a className={i === 0 ? "active" : ""} href="#" key={item}>{item}</a>)}</nav>
      <div className="sidebar-note"><span className="status-dot" /> Preview-only posture<br/><small>Human approval required</small></div>
    </aside>

    <main className="workspace">
      <header className="topbar"><div><p className="eyebrow">TECHNOLOGY RISK / FLEET</p><h1>Operations Overview</h1><p>Evidence-backed endpoint health, risk and recovery decisions.</p></div><div className="top-actions"><span className="pill">● Platform healthy</span><button>Export report</button></div></header>

      {error && <div className="alert error">Unable to load tenant data: {error}</div>}
      {!token && <div className="alert">Demo shell ready. Sign in to load tenant-scoped evidence.</div>}

      <section className="metrics-grid">
        <Stat label="Observed endpoints" value={String(Math.max(metrics.length, diagnosis.length))} detail="Current evidence window" />
        <Stat label="Needs attention" value={String(unhealthy)} detail="Risk above low" />
        <Stat label="Evidence records" value={String(metrics.length + diagnosis.length)} detail="Traceable observations" />
        <Stat label="Execution posture" value="Preview" detail="No autonomous remediation" />
      </section>

      <section className="dashboard-grid">
        <article className="panel chart-panel"><div className="panel-head"><div><p className="eyebrow">NETWORK STATE</p><h2>Connection trend</h2></div><span className="muted">Last 50 observations</span></div>{metrics.length ? <Line data={chartData} options={{ responsive: true, plugins: { legend: { position: "bottom" } } }} /> : <div className="empty">Connection telemetry will appear here.</div>}</article>

        <article className="panel decision-panel"><div className="panel-head"><div><p className="eyebrow">LATEST DECISION</p><h2>Risk assessment</h2></div><span className={`risk-badge ${String(lastDiagnosis?.result?.risk || "unknown").toLowerCase()}`}>{lastDiagnosis?.result?.risk || "No data"}</span></div>
          {lastDiagnosis ? <div className="decision-body"><div><span>Root cause</span><strong>{lastDiagnosis.result.root_cause || "Unclassified"}</strong></div><div><span>Confidence</span><strong>{lastDiagnosis.result.confidence || "—"}</strong></div><div><span>Recommendation</span><p>{lastDiagnosis.result.recommendation || "Collect more evidence before action."}</p></div><button className="secondary">Review evidence →</button></div> : <div className="empty">No diagnosis records yet.</div>}
        </article>
      </section>

      <section className="panel"><div className="panel-head"><div><p className="eyebrow">EVIDENCE → DECISION → ACTION</p><h2>Governance workflow</h2></div><span className="pill neutral">Human in the loop</span></div><div className="workflow">{["Observe", "Classify", "Control test", "Policy gate", "Preview", "Approve", "Verify", "Audit"].map((x, i) => <div className="workflow-step" key={x}><span>{i + 1}</span><b>{x}</b></div>)}</div></section>

      <section className="panel"><div className="panel-head"><div><p className="eyebrow">ANOMALY TRIAGE</p><h2>Latest signals</h2></div></div>{anomaly ? <div className="anomaly"><div><span>Anomaly</span><strong>{String(anomaly.anomaly)}</strong></div><div><span>Reason</span><p>{anomaly.reason}</p></div><pre>{JSON.stringify(anomaly.signals, null, 2)}</pre></div> : <div className="empty">No anomaly payload in the current evidence window.</div>}</section>
    </main>
  </div>;
}
