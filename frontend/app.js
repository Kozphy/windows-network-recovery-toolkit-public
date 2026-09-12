const API_BASE = window.RISK_API_BASE || window.location.origin;

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

function fmt(value, digits = 3) {
  return typeof value === "number" ? value.toFixed(digits) : "—";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function checkHealth() {
  try {
    const health = await api("/api/health");
    $("apiStatus").textContent = health.metrics_present ? "API: ready" : "API: online, models not trained";
    $("apiStatus").classList.add("ok");
  } catch (error) {
    $("apiStatus").textContent = "API: offline";
    $("apiStatus").classList.add("bad");
  }
}

async function loadModels() {
  try {
    const data = await api("/api/models");
    if (!data.models?.length) return;
    const select = $("model");
    select.innerHTML = "";
    data.models.forEach((name) => {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      select.appendChild(option);
    });
  } catch (_) {}
}

async function loadMetrics() {
  const body = $("metricsBody");
  try {
    const data = await api("/api/metrics");
    const entries = Object.entries(data.models || {});
    if (!entries.length) {
      body.innerHTML = '<tr><td colspan="7" class="muted">Train models to populate benchmark metrics.</td></tr>';
      return;
    }
    const rank = new Map((data.ranking_by_f1 || []).map((name, index) => [name, index]));
    entries.sort(([a], [b]) => (rank.get(a) ?? 999) - (rank.get(b) ?? 999));
    body.innerHTML = entries.map(([name, m]) => `
      <tr>
        <td><strong>${escapeHtml(name)}</strong></td>
        <td>${fmt(m.f1)}</td>
        <td>${fmt(m.precision)}</td>
        <td>${fmt(m.recall)}</td>
        <td>${fmt(m.roc_auc)}</td>
        <td>${fmt(m.pr_auc)}</td>
        <td>${fmt(m.brier)}</td>
      </tr>`).join("");
  } catch (error) {
    body.innerHTML = `<tr><td colspan="7" class="muted">Unable to load metrics: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function renderHistory(items) {
  const chart = $("historyChart");
  if (!items.length) {
    chart.className = "history-chart muted";
    chart.textContent = "No persisted predictions yet.";
    $("historyCount").textContent = "0";
    $("latestObservation").textContent = "—";
    return;
  }

  const points = items.slice(-30);
  const width = 620;
  const height = 180;
  const pad = 18;
  const usableWidth = width - pad * 2;
  const usableHeight = height - pad * 2;
  const coords = points.map((item, index) => {
    const x = pad + (points.length === 1 ? usableWidth / 2 : index * usableWidth / (points.length - 1));
    const y = pad + (100 - Math.max(0, Math.min(100, item.risk_score))) * usableHeight / 100;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");

  chart.className = "history-chart";
  chart.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Historical risk score trend">
      <line x1="${pad}" y1="${pad + usableHeight * .25}" x2="${width - pad}" y2="${pad + usableHeight * .25}" class="grid-line" />
      <line x1="${pad}" y1="${pad + usableHeight * .55}" x2="${width - pad}" y2="${pad + usableHeight * .55}" class="grid-line" />
      <polyline points="${coords}" class="risk-line" />
    </svg>`;

  const latest = items[items.length - 1];
  $("historyCount").textContent = String(items.length);
  $("latestObservation").textContent = new Date(latest.observed_at).toLocaleString();
}

async function loadHistory() {
  try {
    const device = $("device_id").value.trim();
    const path = device ? `/api/history?device_id=${encodeURIComponent(device)}&limit=100` : "/api/history?limit=100";
    const data = await api(path);
    renderHistory(data.items || []);
  } catch (error) {
    $("historyChart").textContent = `Unable to load history: ${error.message}`;
  }
}

async function loadExplainability() {
  const target = $("shapBars");
  try {
    const data = await api("/api/explainability?limit=10");
    if (!data.features?.length) {
      target.innerHTML = `<p class="muted">${escapeHtml(data.message || "No SHAP artifact found.")}</p>`;
      return;
    }
    const max = Math.max(...data.features.map((item) => item.mean_abs_shap), 1e-9);
    target.innerHTML = data.features.map((item) => `
      <div class="bar-row">
        <span class="bar-label">${escapeHtml(item.feature)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, item.mean_abs_shap / max * 100).toFixed(1)}%"></div></div>
        <strong>${fmt(item.mean_abs_shap, 4)}</strong>
      </div>`).join("");
  } catch (error) {
    target.innerHTML = `<p class="muted">Unable to load SHAP importance: ${escapeHtml(error.message)}</p>`;
  }
}

async function loadDrift() {
  try {
    const device = $("device_id").value.trim();
    const path = device ? `/api/drift?device_id=${encodeURIComponent(device)}` : "/api/drift";
    const data = await api(path);
    if (data.status !== "ready") {
      $("driftStatus").textContent = `${data.sample_count || 0} samples`;
      $("baselineRisk").textContent = "—";
      $("recentRisk").textContent = "—";
      $("riskDelta").textContent = "—";
      $("driftNote").textContent = data.message || "Insufficient data.";
      return;
    }
    $("driftStatus").textContent = data.direction.toUpperCase();
    $("baselineRisk").textContent = `${data.baseline_mean_risk}/100`;
    $("recentRisk").textContent = `${data.recent_mean_risk}/100`;
    $("riskDelta").textContent = `${data.delta > 0 ? "+" : ""}${data.delta}`;
    $("driftNote").textContent = data.note;
  } catch (error) {
    $("driftNote").textContent = `Unable to load drift indicator: ${error.message}`;
  }
}

$("predictionForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    device_id: $("device_id").value.trim() || "local-device",
    source: "manual",
    model: $("model").value,
    proxy_mismatch: Number($("proxy_mismatch").value),
    dns_failure_rate: Number($("dns_failure_rate").value),
    tls_error_count: Number($("tls_error_count").value),
    adapter_reset_count: Number($("adapter_reset_count").value),
    winhttp_drift: Number($("winhttp_drift").value),
    network_profile: $("network_profile").value,
  };

  $("predictionMessage").textContent = "Running inference…";
  try {
    const result = await api("/api/predict", { method: "POST", body: JSON.stringify(payload) });
    $("riskScore").textContent = `${result.risk_score}/100`;
    $("riskProbability").textContent = `${(result.risk_probability * 100).toFixed(1)}%`;
    $("severity").textContent = result.severity.toUpperCase();
    $("modelName").textContent = result.model;
    $("recommendedAction").textContent = result.recommended_action;
    $("humanApproval").textContent = result.human_approval_required ? "Required" : "Not required";
    $("evidenceSource").textContent = result.source;
    $("governanceNote").textContent = result.governance_note;
    $("predictionMessage").textContent = "Prediction completed and persisted to the local audit history.";
    await Promise.all([loadHistory(), loadDrift()]);
  } catch (error) {
    $("predictionMessage").textContent = `Prediction unavailable: ${error.message}`;
  }
});

$("refreshMetrics").addEventListener("click", loadMetrics);
$("refreshHistory").addEventListener("click", () => Promise.all([loadHistory(), loadDrift()]));
$("refreshExplainability").addEventListener("click", loadExplainability);
$("device_id").addEventListener("change", () => Promise.all([loadHistory(), loadDrift()]));

checkHealth();
loadModels();
loadMetrics();
loadHistory();
loadExplainability();
loadDrift();
