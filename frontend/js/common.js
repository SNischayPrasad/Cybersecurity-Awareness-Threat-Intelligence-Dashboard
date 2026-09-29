/* ==========================================================================
   Shared helpers: navigation, safe DOM building, API calls, badges, charts.
   SECURITY: all dynamic text is inserted with textContent (never innerHTML),
   so threat descriptions or notes cannot inject scripts (XSS).
   ========================================================================== */
"use strict";

const NAV = [
  ["index.html", "Overview"],
  ["threat-dashboard.html", "SOC Dashboard"],
  ["attack.html", "ATT&CK"],
  ["vulnerabilities.html", "Vulnerabilities"],
  ["alerts.html", "Alerts"],
  ["awareness.html", "Awareness Center"],
  ["quiz.html", "Quiz"],
  ["executive.html", "Executive"],
];

const SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SEV_COLORS = {
  INFORMATIONAL: "#898781", LOW: "#3987e5", MEDIUM: "#fab219", HIGH: "#ec835a", CRITICAL: "#d03b3b",
  NONE: "#898781",
};
// Categorical order (validated palette, dark-mode steps). Assigned in fixed order.
const SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];

/* ---------- Safe DOM builder ---------- */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k === "style") el.setAttribute("style", v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function $(sel, root = document) { return root.querySelector(sel); }
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
function fmt(n) { return n === null || n === undefined ? "—" : Number(n).toLocaleString(); }
function titleCase(s) { return String(s || "").toLowerCase().replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()); }
function defang(v) {
  // Display-only: make indicators non-clickable (hxxp, [.]). Hashes and CVE IDs stay as-is.
  if (!v || /^[0-9a-f]+$/i.test(v) || /^CVE-/i.test(v)) return v || "";
  return v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}
function qs(name) { return new URLSearchParams(location.search).get(name); }

/* ---------- API key (per-tab, sessionStorage; never hard-coded) ---------- */
function getKey() { try { return sessionStorage.getItem("apiKey") || ""; } catch (e) { return ""; } }
function setKey(k) { try { k ? sessionStorage.setItem("apiKey", k) : sessionStorage.removeItem("apiKey"); } catch (e) { /* ignore */ } }

async function api(path, options = {}) {
  const headers = Object.assign({ Accept: "application/json" }, options.headers || {});
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const key = getKey();
  if (key) headers["X-API-Key"] = key;
  const res = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (!res.ok) {
    const msg = (data && (data.message || data.error)) || `Request failed (${res.status})`;
    const details = data && data.details ? " " + [].concat(data.details).join(" ") : "";
    const err = new Error(msg + details);
    err.status = res.status;
    throw err;
  }
  return data;
}

/* ---------- Badges ---------- */
function sevBadge(sev) {
  return h("span", { class: `badge sev-${sev}`, title: `Severity: ${sev}` }, h("span", { class: "dot" }), sev);
}
function statusBadge(status) { return h("span", { class: "badge status" }, titleCase(status)); }
function tag(text) { return h("span", { class: "tag" }, text); }

/* ---------- Layout chrome ---------- */
function renderChrome() {
  const page = location.pathname.split("/").pop() || "index.html";
  const strip = h("div", { class: "demo-strip" },
    "SYNTHETIC / DEMO DATA ONLY — defensive education project. Indicators are never visited or contacted.");
  const nav = h("nav", { class: "nav", "aria-label": "Main" },
    NAV.map(([href, label]) => h("a", { href, class: href === page ? "active" : "" }, label)));
  const keyInput = h("input", { type: "password", placeholder: "Analyst API key", value: getKey(), "aria-label": "Analyst API key" });
  const pill = h("span", { class: "role-pill" }, "viewer");
  const save = h("button", { class: "btn ghost small", type: "button" }, "Set key");
  async function refreshRole() {
    try { const r = await api("/api/auth/whoami"); pill.textContent = r.role; }
    catch (e) { pill.textContent = "invalid key"; }
  }
  save.addEventListener("click", () => { setKey(keyInput.value.trim()); refreshRole(); document.dispatchEvent(new Event("rolechange")); });
  const bar = h("header", { class: "topbar" },
    h("a", { class: "brand", href: "index.html" }, h("span", { class: "brand-mark" }, "TI"),
      h("span", {}, "Threat Intel & Awareness", h("small", {}, "SOC CONSOLE · DEFENSIVE"))),
    nav,
    h("div", { class: "key-box", title: "Analyst/admin actions need an API key (see .env)" }, keyInput, save, pill));
  document.body.prepend(strip, bar);
  document.body.append(h("footer", { class: "foot" },
    "Defensive cybersecurity education project. All threat data is synthetic. " +
    "IOC match ≠ confirmed compromise · Risk ≠ Confidence · Correlation ≠ Attribution."));
  refreshRole();
}

/* ---------- Status helpers ---------- */
function showError(container, err) {
  clear(container).append(h("div", { class: "callout danger" }, h("strong", {}, "Error: "), err.message || String(err)));
}
function loading(container, text = "Loading…") { clear(container).append(h("p", { class: "muted" }, text)); }

/* ---------- Charts (Chart.js from CDN, with graceful fallback) ---------- */
function chartsReady() { return typeof window.Chart !== "undefined"; }

function baseChartOptions(extra = {}) {
  return Object.assign({
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 250 },
    plugins: {
      legend: { display: false, labels: { color: "#c3c2b7", boxWidth: 10, boxHeight: 10, usePointStyle: true } },
      tooltip: { backgroundColor: "#222220", borderColor: "rgba(255,255,255,.18)", borderWidth: 1,
        titleColor: "#ffffff", bodyColor: "#c3c2b7", padding: 10, displayColors: true },
    },
    scales: {
      x: { grid: { color: "#2c2c2a", drawTicks: false }, border: { color: "#383835" }, ticks: { color: "#898781", padding: 6 } },
      y: { grid: { color: "#2c2c2a", drawTicks: false }, border: { color: "#383835" }, ticks: { color: "#898781", padding: 6 }, beginAtZero: true },
    },
  }, extra);
}

function fallbackTable(canvas, labels, values) {
  const box = canvas.parentElement;
  clear(box).append(h("p", { class: "chart-fallback" }, "Chart library unavailable (offline?). Data table:"),
    h("table", {}, h("tbody", {}, labels.map((l, i) => h("tr", {}, h("td", {}, l), h("td", { class: "num" }, fmt(values[i])))))));
}

const _charts = {};
function barChart(canvasId, labels, values, opts = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  if (!chartsReady()) { fallbackTable(canvas, labels, values); return null; }
  if (_charts[canvasId]) _charts[canvasId].destroy();
  const horizontal = !!opts.horizontal;
  const options = baseChartOptions();
  if (horizontal) {
    options.indexAxis = "y";
    options.scales.x.beginAtZero = true;
    options.scales.y.grid = { display: false };
  } else {
    options.scales.x.grid = { display: false };
  }
  if (opts.onClick) {
    options.onClick = (evt, els) => { if (els.length) opts.onClick(labels[els[0].index], els[0].index); };
    options.onHover = (evt, els) => { evt.native.target.style.cursor = els.length ? "pointer" : "default"; };
  }
  _charts[canvasId] = new Chart(canvas, {
    type: "bar",
    data: { labels, datasets: [{ label: opts.label || "Count", data: values,
      backgroundColor: opts.colors || SERIES[0], borderRadius: 4, borderSkipped: "start",
      maxBarThickness: 28, categoryPercentage: 0.8, barPercentage: 0.9 }] },
    options,
  });
  return _charts[canvasId];
}

function lineChart(canvasId, labels, datasets, opts = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  if (!chartsReady()) { fallbackTable(canvas, labels, datasets[0].data); return null; }
  if (_charts[canvasId]) _charts[canvasId].destroy();
  const options = baseChartOptions({ interaction: { mode: "index", intersect: false } });
  options.plugins.legend.display = datasets.length > 1;
  options.scales.x.grid = { display: false };
  if (opts.yMax) options.scales.y.max = opts.yMax;
  _charts[canvasId] = new Chart(canvas, {
    type: "line",
    data: { labels, datasets: datasets.map((d, i) => Object.assign({
      borderColor: SERIES[i], backgroundColor: SERIES[i], borderWidth: 2, pointRadius: 0,
      pointHoverRadius: 5, tension: 0.25 }, d)) },
    options,
  });
  return _charts[canvasId];
}

/* ---------- Meter (risk/confidence bar) ---------- */
function meter(label, value, cls = "") {
  return h("div", { class: "meter" },
    h("div", { class: "meter-head" }, h("span", {}, label), h("strong", {}, `${value}`, h("span", { class: "muted small" }, " / 100"))),
    h("div", { class: "meter-track", role: "meter", "aria-valuenow": value, "aria-valuemin": 0, "aria-valuemax": 100, "aria-label": label },
      // For the risk gradient, stretch the gradient across the whole track so colour reflects position.
      h("div", { class: `meter-fill ${cls}`, style: `width:${Math.max(0, Math.min(100, value))}%;` +
        (cls === "risk" ? `background-size:${10000 / Math.max(1, value)}% 100%` : "") })));
}

document.addEventListener("DOMContentLoaded", renderChrome);
