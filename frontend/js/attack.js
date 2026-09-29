"use strict";

async function showRecords(filter, title) {
  $("#records-title").textContent = title;
  const box = $("#records");
  loading(box);
  document.querySelectorAll(".tech").forEach((b) => b.classList.toggle("active", b.dataset.tid === filter.technique_id));
  try {
    const params = new URLSearchParams(Object.assign({ sort: "risk", page_size: 50 }, filter));
    const data = await api("/api/threats?" + params);
    $("#records-count").textContent = `${fmt(data.total)} records (showing up to 50, highest risk first)`;
    clear(box).append(h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Threat ID", "Name", "Category", "Indicator", "Severity", "Risk", "Conf.", "Status"].map((x) => h("th", {}, x)))),
      h("tbody", {}, data.items.map((t) => {
        const tr = h("tr", { class: "clickable" }, h("td", { class: "mono" }, t.threat_id), h("td", {}, t.threat_name),
          h("td", {}, t.category_label), h("td", { class: "mono" }, t.indicator_defanged), h("td", {}, sevBadge(t.severity)),
          h("td", { class: "num" }, t.risk_score), h("td", { class: "num" }, t.confidence_score), h("td", {}, statusBadge(t.status)));
        tr.addEventListener("click", () => { location.href = "threat-details.html?id=" + encodeURIComponent(t.threat_id); });
        return tr;
      })))));
    $("#records-card").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) { showError(box, err); }
}

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const a = await api("/api/attack/summary");
    const total = a.mapped_records + a.unmapped_records;
    clear($("#attack-kpis")).append(
      h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, "Records with ATT&CK mapping"), h("div", { class: "kpi-value" }, fmt(a.mapped_records)),
        h("div", { class: "kpi-note" }, `${Math.round(100 * a.mapped_records / Math.max(1, total))}% of records — behaviour observed`)),
      h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, "Unmapped (insufficient context)"), h("div", { class: "kpi-value" }, fmt(a.unmapped_records)),
        h("div", { class: "kpi-note" }, "feed-only indicators are not guessed")),
      h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, "Distinct techniques observed"), h("div", { class: "kpi-value" }, fmt(a.techniques.length)),
        h("div", { class: "kpi-note" }, `${a.tactics.length} tactics`)));

    barChart("c-tactics", a.tactics.map((t) => t.tactic), a.tactics.map((t) => t.count),
      { horizontal: true, label: "Mapped records", onClick: (l) => showRecords({ tactic: l }, `Tactic: ${l}`) });
    const top = a.techniques.slice(0, 12);
    barChart("c-techniques", top.map((t) => `${t.technique_id_optional} ${t.technique.split(":").pop().trim()}`), top.map((t) => t.count),
      { horizontal: true, label: "Records", onClick: (l, i) => showRecords({ technique_id: top[i].technique_id_optional }, `${top[i].technique_id_optional} · ${top[i].technique}`) });

    const matrix = clear($("#matrix"));
    a.tactic_order.forEach((tactic) => {
      const techs = a.matrix[tactic] || [];
      matrix.append(h("div", { class: "matrix-col" }, h("h3", {}, tactic),
        techs.length ? techs.map((t) => {
          const b = h("button", { class: "tech", type: "button", "data-tid": t.technique_id_optional },
            h("span", { class: "tcount" }, t.count), h("span", { class: "tid" }, t.technique_id_optional), h("span", { class: "tname" }, t.technique));
          b.addEventListener("click", () => showRecords({ technique_id: t.technique_id_optional }, `${t.technique_id_optional} · ${t.technique}`));
          return b;
        }) : h("div", { class: "empty" }, "No mapped records")));
    });
    $("#version-note").textContent = a.version_note + " " + a.note;

    const tactic = qs("tactic");
    if (tactic) showRecords({ tactic }, `Tactic: ${tactic}`);
  } catch (err) { showError($("#attack-kpis"), err); }
});
