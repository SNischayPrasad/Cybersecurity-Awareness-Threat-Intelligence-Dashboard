"use strict";

function rankList(items, label, value) {
  const max = Math.max(1, ...items.map(value));
  return items.map((it) => h("div", { class: "bar-row", style: "grid-template-columns:140px 1fr 44px" },
    h("span", {}, label(it)), h("div", { class: "track" }, h("div", { class: "fill", style: `width:${100 * value(it) / max}%` })),
    h("span", { class: "num" }, fmt(value(it)))));
}

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const e = await api("/api/executive/summary");
    $("#headline").textContent = e.headline;
    const tl = e.threat_landscape;
    const tile = (label, value, note, color) => h("div", { class: "kpi" },
      h("div", { class: "kpi-label" }, color ? h("span", { class: "dot", style: `background:${color}` }) : null, label),
      h("div", { class: "kpi-value" }, value), h("div", { class: "kpi-note" }, note));
    clear($("#exec-kpis")).append(
      tile("Critical + high (active)", fmt(tl.critical_active + tl.high_active), `${tl.critical_active} critical · ${tl.high_active} high`, SEV_COLORS.CRITICAL),
      tile("Open alerts", fmt(tl.open_alerts), `reduced from ${fmt(e.alert_noise_reduction.raw_candidates)} raw signals by correlation`),
      tile("Urgent (P1) vulnerabilities", fmt(e.p1_vulnerabilities), "patch or mitigate within days"),
      tile("Confirmed incidents", fmt(tl.confirmed_incidents), "indicators ≠ incidents"));

    clear($("#priorities")).append(...e.recommended_priorities.map((p) => h("li", {}, p)));
    clear($("#top-cats")).append(...rankList(e.top_threat_categories, (c) => c.label, (c) => c.count));
    clear($("#top-vulns")).append(...rankList(e.top_vulnerability_categories, (v) => v.product_category, (v) => v.p1 || 0));
    clear($("#weak")).append(...rankList(e.awareness.top_weaknesses, (w) => w.category, (w) => w.average));
    clear($("#notes")).append(...e.plain_language_notes.map((n) => h("li", {}, n)));

    const a = e.awareness;
    lineChart("c-aware", a.months, [{ label: "Average awareness score", data: a.average_scores }], { yMax: 100 });
    if (a.starting_average !== null && a.current_average !== null) {
      const delta = Math.round((a.current_average - a.starting_average) * 10) / 10;
      $("#aware-note").textContent = `Average moved from ${a.starting_average} to ${a.current_average} (${delta >= 0 ? "+" : ""}${delta} points). ` +
        "Educational indicator only — not an individual performance measure.";
    }
  } catch (err) { showError($("#exec-kpis"), err); }
});
