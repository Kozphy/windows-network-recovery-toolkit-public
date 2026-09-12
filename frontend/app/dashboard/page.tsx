"use client";

import { useEffect, useMemo, useState } from "react";
import { Line } from "react-chartjs-2";
import {
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from "chart.js";
import { authFetch } from "../../lib/api";
import { supabase } from "../../lib/supabase";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

export default function DashboardPage() {
  const [token, setToken] = useState("");
  const [history, setHistory] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setToken(data.session?.access_token || "");
    });
  }, []);

  useEffect(() => {
    if (!token) return;
    authFetch("/history?limit=50", token)
      .then((data) => {
        setHistory(data);
      })
      .catch((err) => setError(String(err)));
  }, [token]);

  const chartData = useMemo(() => {
    const metrics = (history?.connection_metrics || []).slice().reverse();
    return {
      labels: metrics.map((m: any) => m.timestamp),
      datasets: [
        {
          label: "TIME_WAIT",
          data: metrics.map((m: any) => m.time_wait),
          borderColor: "#ef4444",
        },
        {
          label: "ESTABLISHED",
          data: metrics.map((m: any) => m.established),
          borderColor: "#2563eb",
        },
      ],
    };
  }, [history]);

  const lastDiagnosis = history?.diagnosis_logs?.[0];
  const anomaly = lastDiagnosis?.result?.anomaly;

  return (
    <main className="container">
      <h1>Dashboard</h1>
      {error && <div className="card">Error: {error}</div>}
      {!token && <div className="card">Login first to load tenant-scoped data.</div>}

      <section className="card">
        <h2>Recent Diagnosis</h2>
        {!lastDiagnosis ? (
          <p>No diagnosis records yet.</p>
        ) : (
          <>
            <p>
              <strong>Root Cause:</strong> {lastDiagnosis.result.root_cause}
            </p>
            <p>
              <strong>Confidence:</strong> {lastDiagnosis.result.confidence}
            </p>
            <p>
              <strong>Risk:</strong> {lastDiagnosis.result.risk}
            </p>
            <p>
              <strong>Recommendation:</strong> {lastDiagnosis.result.recommendation}
            </p>
          </>
        )}
      </section>

      <section className="card">
        <h2>Connection Trend</h2>
        <Line data={chartData} />
      </section>

      <section className="card">
        <h2>Anomaly Alert</h2>
        {!anomaly ? (
          <p>No anomaly payload yet.</p>
        ) : (
          <>
            <p>
              <strong>Anomaly:</strong> {String(anomaly.anomaly)}
            </p>
            <p>
              <strong>Reason:</strong> {anomaly.reason}
            </p>
            <pre>{JSON.stringify(anomaly.signals, null, 2)}</pre>
          </>
        )}
      </section>
    </main>
  );
}
