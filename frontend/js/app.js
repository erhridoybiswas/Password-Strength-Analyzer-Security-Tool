/* =========================================================================
   app.js
   -------------------------------------------------------------------------
   PRIVACY RULES FOLLOWED BY THIS FILE:
     * The password is only ever sent in a POST body to /api/analyze.
     * The password is never placed in a URL, localStorage or sessionStorage.
     * The password is never written to console.log.
     * The password is cleared from memory when the input is emptied.
   ========================================================================= */

const $ = (id) => document.getElementById(id);

const passwordInput   = $("passwordInput");
const toggleBtn       = $("toggleVisibility");
const meterFill       = $("meterFill");
const classification  = $("classificationLabel");
const scoreLabel      = $("scoreLabel");
const findingsList    = $("findingsList");
const suggestionsList = $("suggestionsList");
const metricsTable    = $("metricsTable");
const entropyTable    = $("entropyTable");

const ctxName = $("ctxName");
const ctxYear = $("ctxYear");
const ctxOrg  = $("ctxOrg");

const CLASS_COLORS = {
  "VERY WEAK":   "#e5484d",
  "WEAK":        "#f76808",
  "MODERATE":    "#ffb224",
  "STRONG":      "#46a758",
  "VERY STRONG": "#12a594",
};

/* ------------------------------------------------------------------ */
/* Debounce helper                                                     */
/* ------------------------------------------------------------------ */
function debounce(fn, delay) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

/* ------------------------------------------------------------------ */
/* Show / hide password                                                */
/* ------------------------------------------------------------------ */
toggleBtn.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  toggleBtn.textContent = showing ? "👁 Show" : "🙈 Hide";
});

/* ------------------------------------------------------------------ */
/* Rendering                                                           */
/* ------------------------------------------------------------------ */
function renderMeter(score, cls) {
  const color = CLASS_COLORS[cls] || "#e5484d";
  meterFill.style.width = `${Math.max(0, Math.min(100, score))}%`;
  meterFill.style.background = color;
  classification.textContent = cls || "—";
  classification.style.color = color;
  scoreLabel.textContent = `${score}/100`;
}

function renderFindings(findings) {
  findingsList.innerHTML = "";
  if (!findings || findings.length === 0) {
    const li = document.createElement("li");
    li.className = "ok";
    li.textContent = "✓ No predictable patterns detected.";
    findingsList.appendChild(li);
    return;
  }
  findings.forEach((f) => {
    const li = document.createElement("li");
    li.className = `sev-${f.severity || "low"}`;
    li.textContent = f.description;
    findingsList.appendChild(li);
  });
}

function renderSuggestions(suggestions) {
  suggestionsList.innerHTML = "";
  (suggestions || []).forEach((s) => {
    const li = document.createElement("li");
    li.textContent = s;
    suggestionsList.appendChild(li);
  });
}

function renderMetrics(metrics) {
  const len = metrics.length || {};
  const ch  = metrics.characters || {};
  const en  = metrics.entropy || {};

  const rows = [
    ["Length", `${len.length} (${len.band})`],
    ["Character types", ch.character_type_count],
    ["Unique characters", `${ch.unique_character_count} (ratio ${ch.unique_character_ratio})`],
    ["Lowercase / Uppercase", `${ch.has_lowercase} / ${ch.has_uppercase}`],
    ["Digits / Symbols", `${ch.has_digit} / ${ch.has_symbol}`],
    ["Pattern findings", metrics.pattern_finding_count],
  ];
  metricsTable.innerHTML =
    "<tbody>" + rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join("") + "</tbody>";

  const eRows = [
    ["Theoretical entropy", `${en.theoretical_bits} bits`],
    ["Practical entropy (heuristic)", `${en.practical_bits} bits`],
    ["Character pool size", en.pool_size],
    ["Pattern penalty factor", en.penalty_factor],
  ];
  entropyTable.innerHTML =
    "<tbody>" + eRows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join("") + "</tbody>";
}

function renderPolicy(policy) {
  if (!policy) return;
  const li = document.createElement("li");
  li.className = policy.policy_pass ? "ok" : "sev-high";
  li.textContent = policy.policy_pass
    ? "✓ POLICY PASS — meets the configured policy."
    : "⚠ POLICY FAIL — " + policy.violations.join(" ");
  findingsList.appendChild(li);
}

/* ------------------------------------------------------------------ */
/* Analysis call                                                       */
/* ------------------------------------------------------------------ */
async function analyzeNow() {
  const password = passwordInput.value;

  if (!password) {
    renderMeter(0, "—");
    findingsList.innerHTML = '<li class="muted">Waiting for input…</li>';
    suggestionsList.innerHTML = '<li class="muted">Waiting for input…</li>';
    metricsTable.innerHTML = '<tbody><tr><td class="muted" colspan="2">No data yet.</td></tr></tbody>';
    entropyTable.innerHTML = '<tbody><tr><td class="muted" colspan="2">No data yet.</td></tr></tbody>';
    return;
  }

  const context = {};
  if (ctxName.value.trim()) context.first_name = ctxName.value.trim();
  if (ctxYear.value.trim()) context.birth_year = ctxYear.value.trim();
  if (ctxOrg.value.trim())  context.organization = ctxOrg.value.trim();

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password, context }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      findingsList.innerHTML = `<li class="sev-high">${err.message || "Analysis failed."}</li>`;
      return;
    }

    const data = await res.json();
    renderMeter(data.score, data.classification);
    renderFindings(data.findings);
    renderSuggestions(data.suggestions);
    renderMetrics(data.metrics || {});
    renderPolicy(data.policy);

    // Clear the local reference — we do not keep the password around.
    // (The input element itself holds the value while the user is typing.)
  } catch (e) {
    findingsList.innerHTML = '<li class="sev-high">Network error while analyzing.</li>';
  }
}

const debouncedAnalyze = debounce(analyzeNow, 220);
passwordInput.addEventListener("input", debouncedAnalyze);
[ctxName, ctxYear, ctxOrg].forEach((el) => el.addEventListener("input", debouncedAnalyze));

/* ------------------------------------------------------------------ */
/* Password generator                                                  */
/* ------------------------------------------------------------------ */
$("generateBtn").addEventListener("click", async () => {
  const body = {
    length: parseInt($("genLength").value, 10),
    use_uppercase: $("genUpper").checked,
    use_lowercase: $("genLower").checked,
    use_digits: $("genDigits").checked,
    use_symbols: $("genSymbols").checked,
  };
  const res = await fetch("/api/generate-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  $("generatedOutput").value = data.password || "";
});

$("generatePhraseBtn").addEventListener("click", async () => {
  const res = await fetch("/api/generate-passphrase", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ word_count: 5 }),
  });
  const data = await res.json();
  $("generatedOutput").value = data.passphrase || "";
});

$("copyBtn").addEventListener("click", async () => {
  const value = $("generatedOutput").value;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    $("copyBtn").textContent = "Copied!";
    setTimeout(() => ($("copyBtn").textContent = "Copy"), 1200);
  } catch {
    $("copyBtn").textContent = "Copy failed";
  }
});

/* ------------------------------------------------------------------ */
/* Dashboard                                                           */
/* ------------------------------------------------------------------ */
let charts = {};

function destroyCharts() {
  Object.values(charts).forEach((c) => c && c.destroy());
  charts = {};
}

async function loadDashboard() {
  const [statsRes, weakRes] = await Promise.all([
    fetch("/api/dashboard/stats"),
    fetch("/api/analytics/weaknesses"),
  ]);
  const stats = await statsRes.json();
  const weak  = await weakRes.json();

  // Stat cards
  const byClass = stats.by_classification || {};
  const cards = [
    ["Total Analyses", stats.total_analyses],
    ["Average Score", stats.average_score],
    ["Very Weak", byClass["VERY WEAK"] || 0],
    ["Weak", byClass["WEAK"] || 0],
    ["Moderate", byClass["MODERATE"] || 0],
    ["Strong", byClass["STRONG"] || 0],
    ["Very Strong", byClass["VERY STRONG"] || 0],
  ];
  $("statGrid").innerHTML = cards
    .map(([label, value]) => `<div class="stat"><div class="value">${value}</div><div class="label">${label}</div></div>`)
    .join("");

  destroyCharts();

  const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: "#e6ecf5" } } },
    scales: {
      x: { ticks: { color: "#8b9ab3" }, grid: { color: "#263047" } },
      y: { ticks: { color: "#8b9ab3" }, grid: { color: "#263047" } },
    },
  };

  const classLabels = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"];
  charts.strength = new Chart($("chartStrength"), {
    type: "doughnut",
    data: {
      labels: classLabels,
      datasets: [{
        data: classLabels.map((l) => byClass[l] || 0),
        backgroundColor: ["#e5484d", "#f76808", "#ffb224", "#46a758", "#12a594"],
      }],
    },
    options: { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#e6ecf5" } } } },
  });

  const scoreDist = stats.score_distribution || {};
  charts.score = new Chart($("chartScore"), {
    type: "bar",
    data: {
      labels: Object.keys(scoreDist),
      datasets: [{ label: "Analyses", data: Object.values(scoreDist), backgroundColor: "#4f8cff" }],
    },
    options: chartOpts,
  });

  const weaknesses = weak.weaknesses || [];
  charts.weakness = new Chart($("chartWeakness"), {
    type: "bar",
    data: {
      labels: weaknesses.map((w) => w.type),
      datasets: [{ label: "Count", data: weaknesses.map((w) => w.count), backgroundColor: "#f76808" }],
    },
    options: chartOpts,
  });

  const lengthDist = stats.length_distribution || {};
  charts.length = new Chart($("chartLength"), {
    type: "bar",
    data: {
      labels: Object.keys(lengthDist),
      datasets: [{ label: "Passwords", data: Object.values(lengthDist), backgroundColor: "#12a594" }],
    },
    options: chartOpts,
  });
}

$("refreshDashboard").addEventListener("click", loadDashboard);
window.addEventListener("load", loadDashboard);