/**
 * @file Static platform dashboard helpers (vanilla JS) served with the FastAPI portfolio UI.
 *
 * @remarks
 * Fetches read-oriented `/health`, `/platform/audit/logs`, and replay endpoints into
 * DOM panels. Not the NiceGUI monitoring dashboard (`python -m windows_network_toolkit dashboard`).
 *
 * Side effects: browser `fetch` only. No registry or remediations.
 *
 * Audit notes: failed fetches render `{ error }` in the panel — check backend reachability
 * and that audit JSONL exists before treating empty panels as "healthy".
 */

async function fetchJson(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
}

function setPanel(id, data, emptyMsg) {
  const el = document.querySelector(`#${id} .panel`) || document.getElementById(id);
  const target = el.classList && el.classList.contains("panel") ? el : document.querySelector(`#${id} pre`);
  if (!data || (Array.isArray(data) && data.length === 0)) {
    target.textContent = emptyMsg || "No data.";
    target.classList.add("empty");
    return;
  }
  target.classList.remove("empty");
  target.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
}

async function loadHealth() {
  try {
    const h = await fetchJson("/health");
    setPanel("health", h);
  } catch (e) {
    setPanel("health", { error: String(e) });
  }
}

async function loadAudit() {
  try {
    const a = await fetchJson("/platform/audit/logs?limit=10");
    setPanel("audit", a.logs || [], "No audit rows yet.");
  } catch (e) {
    setPanel("audit", { error: String(e) });
  }
}

async function runReplay() {
  const out = document.getElementById("replay-out");
  out.textContent = "Replaying…";
  try {
    const body = await fetchJson("/platform/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fixture_path: "proxy_drift_incident.jsonl", dry_run: true }),
    });
    setPanel("timeline", body.timeline || [], "No timeline.");
    setPanel("evidence", body.timeline || [], "No evidence.");
    setPanel("decision", body.decision, "No decision.");
    setPanel("risk", { risk_level: body.decision?.risk_level, confidence: body.confidence });
    setPanel("policy", body.policy, "No policy.");
    setPanel("confirm", {
      requires_confirmation: body.decision?.requires_confirmation,
      recommended_action: body.decision?.recommended_action,
    });
    setPanel("proxy", body.timeline?.find((e) => e.signal?.includes("PROXY")) || "See timeline.");
    setPanel("process", body.timeline?.find((e) => String(e.observed_value).includes("node")) || "—");
    setPanel("registry", body.timeline?.find((e) => e.signal?.includes("REGISTRY") || e.signal?.includes("PROXY_ENABLE")) || "—");
    out.textContent = JSON.stringify(body, null, 2);
    out.classList.remove("empty");
  } catch (e) {
    out.textContent = String(e);
  }
}

document.getElementById("btn-replay").addEventListener("click", runReplay);
loadHealth();
loadAudit();
