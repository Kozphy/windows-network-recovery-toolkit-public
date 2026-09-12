"use client";

import { useEffect, useState } from "react";
import { authFetch } from "../../lib/api";
import { supabase } from "../../lib/supabase";

export default function BillingPage() {
  const [token, setToken] = useState("");
  const [usage, setUsage] = useState<any>(null);
  const [error, setError] = useState("");
  const [orgId, setOrgId] = useState("");

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setToken(data.session?.access_token || "");
    });
  }, []);

  useEffect(() => {
    if (!token) return;
    authFetch("/usage", token)
      .then((data) => {
        setUsage(data);
        setOrgId(data.org_id || "");
      })
      .catch((err) => setError(String(err)));
  }, [token]);

  const upgrade = async (priceId: string) => {
    if (!token || !orgId) return;
    try {
      const payload = {
        org_id: orgId,
        price_id: priceId,
        success_url: window.location.origin + "/billing",
        cancel_url: window.location.origin + "/billing",
      };
      const session = await authFetch("/create-checkout-session", token, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (session.checkout_url) {
        window.location.href = session.checkout_url;
      }
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <main className="container">
      <h1>Billing</h1>
      {error && <div className="card">Error: {error}</div>}
      {!usage ? (
        <div className="card">Login and load usage data first.</div>
      ) : (
        <>
          <section className="card">
            <h2>Current Plan</h2>
            <p>
              <strong>Plan:</strong> {usage.plan}
            </p>
            <p>
              <strong>Status:</strong> {usage.status}
            </p>
            <p>
              <strong>Month:</strong> {usage.month}
            </p>
            <p>
              <strong>Diagnoses:</strong> {usage.diagnosis_count}
            </p>
            <p>
              <strong>Limit:</strong> {usage.limit}
            </p>
            <p>
              <strong>Remaining:</strong> {usage.remaining}
            </p>
          </section>

          <section className="card">
            <h2>Upgrade</h2>
            <p>Use your Stripe price IDs in environment-backed backend config.</p>
            <button onClick={() => upgrade("price_pro_plan")}>Upgrade to Pro</button>
            <span> </span>
            <button onClick={() => upgrade("price_team_plan")}>Upgrade to Team</button>
          </section>
        </>
      )}
    </main>
  );
}
