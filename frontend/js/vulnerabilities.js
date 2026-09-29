"use strict";

const EXPLOIT_LABEL = {
  NO_KNOWN_EXPLOITATION: "None known", PUBLIC_POC_DEMO: "Public PoC", EXPLOITATION_REPORTED_DEMO: "Exploited (reported)",
};

function priorityResult(r) {
  return h("div", { class: "section" },
    h("div", { class: "row" }, h("div", { class: "score-hero", style: "font-size:40px" }, r.priority_score),
      h("div", {}, h("div", { class: "badge label" }, r.priority_band), h("div", { class: "small" }, r.recommended_timeline))),
    h("ul", { style: "margin-top:8px" }, r.rationale.map((x) => h("li", {}, x))));
}

function compareCard(v, heading) {
  return h("div", { class: "callout" + (v.priority_band === "P1" ? " danger" : "") },
    h("div", { class: "small muted" }, heading),
    h("strong", {}, `${v.cve_id} · CVSS ${v.cvss_score}`),
    h("p", { class: "small", style: "margin:6px 0" }, `${v.product_category} · ${titleCase(v.asset_criticality)} criticality · ${titleCase(v.exposure)} · ${EXPLOIT_LABEL[v.exploitation_status_demo]}`),
    h("div", {}, "Contextual priority: ", h("strong", {}, `${v.priority_score} (${v.priority_band})`)));
}

async function loadTable() {
  const params = new URLSearchParams({ sort: $("#vsort").value });
  if ($("#vband").value) params.set("band", $("#vband").value);
  const body = $("#vrows");
  try {
    const data = await api("/api/vulnerabilities?" + params);
    $("#vcount").textContent = `${data.count} records`;
    clear(body).append(...data.items.map((v) => h("tr", {},
      h("td", { class: "mono" }, v.cve_id), h("td", {}, v.product_category), h("td", {}, sevBadge(v.severity)),
      h("td", { class: "num" }, v.cvss_score.toFixed(1)), h("td", {}, titleCase(v.asset_criticality)), h("td", {}, titleCase(v.exposure)),
      h("td", {}, EXPLOIT_LABEL[v.exploitation_status_demo] || v.exploitation_status_demo), h("td", {}, v.patch_available ? "Yes" : "No"),
      h("td", { class: "num" }, v.priority_score.toFixed(1)), h("td", {}, h("span", { class: "badge label" }, v.priority_band)))));
    return data;
  } catch (err) { clear(body).append(h("tr", {}, h("td", { colspan: 10, class: "error" }, err.message))); return null; }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("#calc").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const out = $("#calc-result");
    try {
      const r = await api("/api/vulnerabilities/prioritize", { method: "POST", body: {
        cvss_score: parseFloat(f.cvss_score.value), asset_criticality: f.asset_criticality.value, exposure: f.exposure.value,
        exploitation_status: f.exploitation_status.value, handles_sensitive_data: f.handles_sensitive_data.value === "true",
        patch_available: f.patch_available.value === "true" } });
      clear(out).append(priorityResult(r));
    } catch (err) { showError(out, err); }
  });
  $("#vsort").addEventListener("change", loadTable);
  $("#vband").addEventListener("change", loadTable);

  const data = await loadTable();
  if (!data) return;
  const s = data.stats;
  const a = data.items.find((v) => v.cve_id === "CVE-2099-0001");
  const b = data.items.find((v) => v.cve_id === "CVE-2099-0002");
  if (a && b) {
    clear($("#compare")).append(compareCard(a, "Critical CVSS, isolated test asset"), compareCard(b, "High CVSS, internet-facing critical system"));
    $("#compare").after(h("p", { class: "small", style: "margin-top:10px" },
      "The lower-CVSS vulnerability is more urgent: it is reachable by anyone, protects a critical system and is reportedly exploited."));
  }
  const sev = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  barChart("c-vsev", sev, sev.map((k) => s.by_severity[k] || 0), { colors: sev.map((k) => SEV_COLORS[k]), label: "Vulnerabilities" });
  const bands = ["P1", "P2", "P3", "P4"];
  barChart("c-band", bands, bands.map((k) => s.by_priority_band[k] || 0), { label: "Vulnerabilities" });
  barChart("c-prod", s.by_product.map((p) => p.product_category), s.by_product.map((p) => p.avg_priority), { horizontal: true, label: "Avg priority" });
});
