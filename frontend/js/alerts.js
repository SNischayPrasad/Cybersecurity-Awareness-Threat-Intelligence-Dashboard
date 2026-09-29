"use strict";

const ALERT_STATUSES = ["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"];

function statusControl(a) {
  const sel = h("select", { "aria-label": `Status for ${a.alert_id}` },
    ALERT_STATUSES.map((s) => h("option", { value: s, selected: s === a.status }, titleCase(s))));
  const msg = h("div", { class: "small" });
  sel.addEventListener("change", async () => {
    msg.textContent = "";
    try {
      await api(`/api/alerts/${encodeURIComponent(a.alert_id)}/status`, { method: "PUT", body: { status: sel.value } });
      msg.className = "small success"; msg.textContent = "Saved";
      loadSummary();
    } catch (err) { msg.className = "small error"; msg.textContent = err.message; sel.value = a.status; }
  });
  return h("div", {}, sel, msg);
}

async function loadSummary() {
  const s = await api("/api/alerts/summary");
  const open = (s.by_status.NEW || 0) + (s.by_status.INVESTIGATING || 0);
  const reduction = s.raw_candidates ? Math.round(100 * (s.raw_candidates - s.after_correlation) / s.raw_candidates) : 0;
  clear($("#alert-kpis")).append(
    h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, "Open alerts"), h("div", { class: "kpi-value" }, fmt(open)), h("div", { class: "kpi-note" }, "New + investigating")),
    h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, "Raw alert candidates"), h("div", { class: "kpi-value" }, fmt(s.raw_candidates)), h("div", { class: "kpi-note" }, "before correlation")),
    h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, "After correlation"), h("div", { class: "kpi-value" }, fmt(s.after_correlation)), h("div", { class: "kpi-note" }, `${reduction}% fewer alerts for analysts`)),
    h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, "Alert fatigue"), h("div", { class: "kpi-note", style: "font-size:12.5px;color:var(--ink-2)" },
      "100 sightings of one IP in 5 minutes become 1 alert with observation count 100 — so real signals are not buried.")));
  const typeSel = $("#f-type");
  if (typeSel.options.length === 1) Object.keys(s.by_type).forEach((t) => typeSel.append(h("option", { value: t }, titleCase(t))));
}

async function loadAlerts() {
  const params = new URLSearchParams({ limit: 300 });
  if ($("#f-status").value) params.set("status", $("#f-status").value);
  if ($("#f-sev").value) params.set("severity", $("#f-sev").value);
  if ($("#f-type").value) params.set("alert_type", $("#f-type").value);
  const focus = qs("focus");
  if (focus) params.delete("status");
  const body = $("#arows");
  try {
    const data = await api("/api/alerts?" + params);
    $("#acount").textContent = `${data.count} alerts shown`;
    clear(body);
    data.items.forEach((a) => {
      const tr = h("tr", { id: a.alert_id, style: a.alert_id === focus ? "outline:2px solid var(--accent)" : null },
        h("td", { class: "mono" }, a.alert_id),
        h("td", { class: "small" }, titleCase(a.alert_type)),
        h("td", {}, sevBadge(a.severity)),
        h("td", { class: "num" }, a.risk_score ?? "—"),
        h("td", { class: "num" }, a.confidence_score ?? "—"),
        h("td", { class: "num" }, fmt(a.observation_count)),
        h("td", { class: "small" }, a.description),
        h("td", { class: "mono" }, a.threat_id ? h("a", { href: "threat-details.html?id=" + encodeURIComponent(a.threat_id) }, a.threat_id) : (a.vulnerability_cve || "—")),
        h("td", {}, statusControl(a)));
      body.append(tr);
    });
    if (focus && document.getElementById(focus)) document.getElementById(focus).scrollIntoView({ block: "center" });
  } catch (err) { clear(body).append(h("tr", {}, h("td", { colspan: 9, class: "error" }, err.message))); }
}

function roleHint() {
  $("#role-hint").textContent = getKey() ? "Status changes are saved with your API key and written to the audit log."
    : "Read-only: set an analyst API key (top right) to change alert status.";
}

document.addEventListener("DOMContentLoaded", async () => {
  ["#f-status", "#f-sev", "#f-type"].forEach((id) => $(id).addEventListener("change", loadAlerts));
  document.addEventListener("rolechange", roleHint);
  roleHint();
  try { await loadSummary(); } catch (err) { showError($("#alert-kpis"), err); }
  loadAlerts();
});
