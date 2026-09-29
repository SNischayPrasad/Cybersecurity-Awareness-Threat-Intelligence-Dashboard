"use strict";

let state = { page: 1, pages: 1 };
let categoryLabels = {};

function kpi(label, value, note, color) {
  return h("div", { class: "kpi" },
    h("div", { class: "kpi-label" }, color ? h("span", { class: "dot", style: `background:${color}` }) : null, label),
    h("div", { class: "kpi-value" }, value),
    note ? h("div", { class: "kpi-note" }, note) : null);
}

function renderKpis(c) {
  clear($("#kpis")).append(
    kpi("Total threat records", fmt(c.total_threats), "synthetic intelligence items"),
    kpi("Critical threats", fmt(c.critical_threats), "risk 81–100", SEV_COLORS.CRITICAL),
    kpi("High threats", fmt(c.high_threats), "risk 61–80", SEV_COLORS.HIGH),
    kpi("Active indicators", fmt(c.active_indicators), "new / review / monitoring"),
    kpi("Open investigations", fmt(c.open_investigations), "alerts NEW + INVESTIGATING"),
    kpi("Average confidence", `${c.average_confidence}%`, "evidence quality"),
    kpi("Vulnerabilities tracked", fmt(c.vulnerabilities_tracked), "synthetic CVE-2099-*"),
  );
}

function setFilterAndLoad(name, value) {
  const f = $("#filters");
  f.elements[name].value = value;
  state.page = 1;
  loadTable();
  $("#table-section").scrollIntoView({ behavior: "smooth" });
}

function renderCharts(s, trends) {
  lineChart("c-trend", trends.labels, [
    { label: "All records", data: trends.total },
    { label: "High + critical", data: trends.high_or_critical },
  ]);
  const sevLabels = SEVERITIES;
  barChart("c-sev", sevLabels, sevLabels.map((k) => s.by_severity[k] || 0),
    { colors: sevLabels.map((k) => SEV_COLORS[k]), label: "Records", onClick: (l) => setFilterAndLoad("severity", l) });

  const cats = Object.keys(s.by_category);
  barChart("c-cat", cats.map((c) => categoryLabels[c] || c), cats.map((c) => s.by_category[c]),
    { horizontal: true, label: "Records", onClick: (l, i) => setFilterAndLoad("category", cats[i]) });

  const types = Object.keys(s.by_indicator_type);
  barChart("c-ioc", types, types.map((t) => s.by_indicator_type[t]),
    { label: "Indicators", onClick: (l) => setFilterAndLoad("indicator_type", l) });

  barChart("c-tactic", s.top_tactics.map((t) => t.tactic), s.top_tactics.map((t) => t.count),
    { horizontal: true, label: "Mapped records", onClick: (l) => { location.href = "attack.html?tactic=" + encodeURIComponent(l); } });

  barChart("c-risk", s.risk_distribution.labels, s.risk_distribution.counts, { label: "Records" });
  barChart("c-conf", s.confidence_distribution.labels, s.confidence_distribution.counts, { label: "Records" });

  const vsev = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  barChart("c-vuln", vsev, vsev.map((k) => s.vulnerabilities_by_severity[k] || 0),
    { colors: vsev.map((k) => SEV_COLORS[k]), label: "Vulnerabilities" });

  barChart("c-topcat", s.top_categories_by_risk.map((c) => categoryLabels[c.category] || c.category),
    s.top_categories_by_risk.map((c) => c.avg_risk), { horizontal: true, label: "Average risk" });

  const statuses = s.status_order;
  barChart("c-status", statuses.map(titleCase), statuses.map((k) => s.by_status[k] || 0),
    { label: "Records", onClick: (l, i) => setFilterAndLoad("status", statuses[i]) });
}

function fillSelects(s) {
  const f = $("#filters");
  SEVERITIES.forEach((v) => f.elements.severity.append(h("option", { value: v }, titleCase(v))));
  Object.entries(categoryLabels).forEach(([k, v]) => f.elements.category.append(h("option", { value: k }, v)));
  s.status_order.forEach((v) => f.elements.status.append(h("option", { value: v }, titleCase(v))));
}

async function loadTable() {
  const params = new URLSearchParams();
  for (const el of $("#filters").elements) {
    if (el.name && el.value) params.set(el.name, el.value);
  }
  params.set("page", state.page);
  params.set("page_size", 20);
  const body = $("#threat-rows");
  try {
    const data = await api("/api/threats?" + params.toString());
    state.pages = Math.max(1, data.pages);
    clear(body);
    if (!data.items.length) body.append(h("tr", {}, h("td", { colspan: 10, class: "muted" }, "No threats match these filters.")));
    data.items.forEach((t) => {
      const tr = h("tr", { class: "clickable", tabindex: 0, title: "Open investigation view" },
        h("td", { class: "mono" }, t.threat_id),
        h("td", {}, t.threat_name),
        h("td", {}, t.category_label),
        h("td", {}, h("span", { class: "mono" }, t.indicator_defanged), " ", tag(t.indicator_type)),
        h("td", {}, sevBadge(t.severity)),
        h("td", { class: "num" }, t.risk_score),
        h("td", { class: "num" }, t.confidence_score),
        h("td", { class: "mono" }, t.first_seen),
        h("td", { class: "mono" }, t.last_seen),
        h("td", {}, statusBadge(t.status)));
      const open = () => { location.href = "threat-details.html?id=" + encodeURIComponent(t.threat_id); };
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
      body.append(tr);
    });
    $("#table-count").textContent = `${fmt(data.total)} matching records`;
    $("#page-info").textContent = `Page ${data.page} of ${state.pages}`;
    $("#prev").disabled = state.page <= 1;
    $("#next").disabled = state.page >= state.pages;
  } catch (err) {
    clear(body).append(h("tr", {}, h("td", { colspan: 10, class: "error" }, err.message)));
  }
}

function resultRow(label, value) { return [h("dt", {}, label), h("dd", {}, value)]; }

async function searchIndicator(q) {
  const out = $("#search-result");
  loading(out, "Looking up in the local database (no network contact)…");
  try {
    const r = await api("/api/indicators/search?q=" + encodeURIComponent(q));
    clear(out);
    const v = r.validation;
    if (!v.valid) {
      out.append(h("div", { class: "callout warn" }, h("strong", {}, "Not a valid indicator. "), v.validation_notes.join(" ")));
      return;
    }
    const left = h("dl", { class: "kv" },
      resultRow("Indicator", h("span", { class: "mono" }, r.defanged)),
      resultRow("Indicator type", `${r.indicator_type}${r.subtype ? " (" + r.subtype + ")" : ""}`),
      resultRow("Known in demo dataset", r.known_in_dataset ? "YES" : "NO"));
    if (r.record_count) {
      left.append(
        ...resultRow("Risk", `${r.risk_score}/100`),
        ...resultRow("Severity", sevBadge(r.severity)),
        ...resultRow("Confidence", `${r.confidence_score}%`),
        ...resultRow("Associated category", r.associated_category_labels.join(", ")),
        ...resultRow("First seen", r.first_seen),
        ...resultRow("Last seen", r.last_seen),
        ...resultRow("Status", statusBadge(r.status)),
        ...resultRow("Records / observations", `${r.record_count} records · ${fmt(r.total_observations)} observations`),
        ...resultRow("Sources", r.sources.join(", ")),
        ...resultRow("Primary record", h("a", { href: "threat-details.html?id=" + encodeURIComponent(r.primary_threat_id) }, r.primary_threat_id + " →")));
    }
    const right = h("div", { class: "stack" },
      h("div", { class: "callout" }, h("strong", {}, "Network activity: "), r.network_activity),
      r.caution ? h("div", { class: "callout warn" }, r.caution) : null,
      r.message ? h("div", { class: "callout" }, r.message) : null,
      r.interpretation ? h("p", {}, h("strong", {}, "Interpretation: "), r.interpretation) : null,
      h("div", {}, h("h3", {}, "Local context"), h("ul", {}, (r.local_context || []).map((x) => h("li", {}, x)))),
      r.related_indicators && r.related_indicators.length ? h("div", {}, h("h3", {}, "Related indicators"),
        h("ul", {}, r.related_indicators.slice(0, 8).map((x) => h("li", {}, tag(x.indicator_type), " ", h("span", { class: "mono" }, x.defanged))))) : null,
      r.attack_mappings && r.attack_mappings.length ? h("div", {}, h("h3", {}, "ATT&CK"),
        h("ul", {}, r.attack_mappings.map((m) => h("li", {}, `${m.tactic} → ${m.technique} (${m.technique_id_optional})`)))) : null,
      r.vulnerability ? h("div", {}, h("h3", {}, "Vulnerability"),
        h("p", {}, `${r.vulnerability.cve_id} · CVSS ${r.vulnerability.cvss_score} · priority ${r.vulnerability.priority_score} (${r.vulnerability.priority_band})`)) : null,
    );
    out.append(h("div", { class: "grid grid-2" }, h("div", {}, left), right));
  } catch (err) { showError(out, err); }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("#search-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = $("#search-q").value.trim();
    if (q) searchIndicator(q);
  });
  $("#filters").addEventListener("submit", (e) => { e.preventDefault(); state.page = 1; loadTable(); });
  $("#reset").addEventListener("click", () => setTimeout(() => { state.page = 1; loadTable(); }, 0));
  $("#prev").addEventListener("click", () => { if (state.page > 1) { state.page--; loadTable(); } });
  $("#next").addEventListener("click", () => { if (state.page < state.pages) { state.page++; loadTable(); } });

  const q = qs("q");
  if (q) { $("#search-q").value = q; searchIndicator(q); }

  try {
    const [s, trends, health] = await Promise.all([api("/api/dashboard/stats"), api("/api/dashboard/trends"), api("/api/health")]);
    categoryLabels = s.category_labels;
    $("#ref-date").textContent = "Dataset date: " + (health.dataset_reference_date || "—");
    renderKpis(s.cards);
    fillSelects(s);
    renderCharts(s, trends);
    loadTable();
  } catch (err) {
    showError($("#kpis"), err);
  }
});
