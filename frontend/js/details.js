"use strict";

const STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"];

function kvRows(pairs) {
  return h("dl", { class: "kv" }, pairs.filter(Boolean).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")]));
}

function card(title, sub, ...body) {
  return h("section", { class: "card" },
    h("div", { class: "card-title" }, h("h2", {}, title), sub ? h("span", { class: "card-sub" }, sub) : null), ...body);
}

function render(t) {
  const root = clear($("#detail"));
  document.title = `${t.threat_id} · Threat Investigation`;

  // ----- Header -----
  root.append(h("div", { class: "page-head" },
    h("div", {},
      h("div", { class: "eyebrow" }, `${t.threat_id} · ${t.category_label}`),
      h("h1", {}, t.threat_name),
      h("div", { class: "row" }, sevBadge(t.severity), statusBadge(t.status),
        h("span", { class: "badge label" }, `Evidence level: ${t.evidence_level.level}`),
        h("span", { class: "badge label" }, t.data_label || "SYNTHETIC / DEMO ONLY"))),
  ));
  root.append(h("div", { class: "callout", style: "margin-bottom:16px" }, t.evidence_level.explanation));

  // ----- Scores -----
  const b = t.risk_breakdown || {};
  const comp = b.components || {};
  const weighted = b.weighted || {};
  const breakdown = h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Risk factor"), h("th", { class: "num" }, "Input (0-100)"), h("th", { class: "num" }, "Weighted"))),
    h("tbody", {}, Object.keys(comp).map((k) => h("tr", {}, h("td", {}, titleCase(k)), h("td", { class: "num" }, Math.round(comp[k])), h("td", { class: "num" }, weighted[k])))));

  const scores = card("Risk & confidence", "two different questions",
    meter("Risk score — how concerning", t.risk_score, "risk"),
    meter("Confidence score — how sure we are", t.confidence_score),
    h("p", {}, h("strong", {}, "Interpretation: "), t.interpretation),
    h("div", { class: "table-wrap" }, breakdown),
    h("p", { class: "small muted", style: "margin-top:8px" }, `Scored relative to ${b.reference_date || "dataset date"}. High risk ≠ confirmed compromise.`));

  const overview = card("Threat record", null,
    kvRows([
      ["Threat ID", h("span", { class: "mono" }, t.threat_id)],
      ["Category", t.category_label],
      ["Description", t.description],
      ["Indicator type", t.indicator_type],
      ["Indicator value", h("span", { class: "mono" }, t.indicator_defanged)],
      ["Source", `${t.source.source_name} (${t.source.source_type})`],
      ["Source reliability", `${t.source.reliability} – ${t.source.reliability_label}`],
      ["First seen", t.first_seen], ["Last seen", t.last_seen],
      ["Observations", fmt(t.observation_count)],
      ["Campaign", t.campaign_id || "—"],
      ["Region (optional)", t.region || "—"],
      ["Behaviour observed", titleCase(t.behavior_observed)],
    ]),
    h("p", { class: "small muted", style: "margin-top:10px" }, "Indicators are shown defanged ([.] / hxxp) so they cannot be clicked. They are never visited."));

  root.append(h("div", { class: "grid grid-2" }, overview, scores));

  // ----- ATT&CK + CVE + indicators -----
  const attack = card("MITRE ATT&CK mapping", "behaviour-based",
    t.attack_mappings.length
      ? h("div", { class: "stack" }, t.attack_mappings.map((m) => kvRows([
        ["Tactic (why)", m.tactic], ["Technique (how)", m.technique],
        ["Technique ID", h("span", { class: "mono" }, m.technique_id_optional || "—")],
        ["Basis", m.mapping_basis],
        ["Reference", h("span", { class: "mono small" }, m.reference_url || "—")]])))
      : h("div", { class: "callout warn" }, t.attack_mapping_note),
    h("p", { class: "small muted", style: "margin-top:10px" }, "IOC = what artifact was seen. ATT&CK = how the observed behaviour relates to adversary techniques."));

  const indicators = card("Indicators", `${t.indicators.length} on this record`,
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Type"), h("th", {}, "Value (defanged)"), h("th", {}, "Role"))),
      h("tbody", {}, t.indicators.map((i) => h("tr", {}, h("td", {}, tag(i.indicator_type)),
        h("td", { class: "mono" }, i.defanged), h("td", {}, i.is_primary ? "Primary" : "Related")))))),
    t.vulnerability ? h("div", { style: "margin-top:12px" }, h("h3", {}, "CVE association"),
      kvRows([["CVE", t.vulnerability.cve_id], ["CVSS", `${t.vulnerability.cvss_score} (${t.vulnerability.severity})`],
        ["Patch available", t.vulnerability.patch_available ? "Yes" : "No"],
        ["Contextual priority", `${t.vulnerability.priority_score} (${t.vulnerability.priority_band})`]])) : null);

  root.append(h("div", { class: "grid grid-2 section" }, attack, indicators));

  // ----- Related threats & alerts -----
  const related = card("Related threats", "correlation ≠ attribution",
    t.related_threats.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "ID"), h("th", {}, "Indicator"), h("th", {}, "Severity"), h("th", { class: "num" }, "Risk"), h("th", {}, "Link"))),
      h("tbody", {}, t.related_threats.map((r) => {
        const tr = h("tr", { class: "clickable" }, h("td", { class: "mono" }, r.threat_id),
          h("td", {}, tag(r.indicator_type), " ", h("span", { class: "mono" }, defang(r.indicator_value))),
          h("td", {}, sevBadge(r.severity)), h("td", { class: "num" }, r.risk_score), h("td", { class: "small" }, r.relationship));
        tr.addEventListener("click", () => { location.href = "threat-details.html?id=" + encodeURIComponent(r.threat_id); });
        return tr;
      })))) : h("p", { class: "muted" }, "No related records found."));

  const alerts = card("Related alerts", null,
    t.related_alerts.length ? h("ul", {}, t.related_alerts.map((a) => h("li", {},
      h("a", { href: "alerts.html?focus=" + encodeURIComponent(a.alert_id) }, a.alert_id), " · ", titleCase(a.alert_type), " · ",
      sevBadge(a.severity), " ", statusBadge(a.status), a.observation_count > 1 ? ` · ${a.observation_count} observations` : "")))
      : h("p", { class: "muted" }, "No alerts reference this record."));

  root.append(h("div", { class: "grid grid-2 section" }, related, alerts));

  // ----- Timeline + notes + actions -----
  const timeline = card("Threat timeline", "lifecycle",
    h("ul", { class: "timeline" }, t.timeline.map((e) => h("li", { class: e.event_type },
      h("div", { class: "when" }, e.event_time), h("div", { class: "what" }, e.event_type.replace(/_/g, " ")),
      h("div", { class: "detail" }, e.detail)))));

  const noteList = h("div", { class: "stack" }, t.analyst_notes.length
    ? t.analyst_notes.map((n) => h("div", { class: "callout" }, h("div", { class: "small muted" }, `${n.author} · ${n.created_at}`), n.note))
    : h("p", { class: "muted" }, "No analyst notes yet."));
  const noteText = h("textarea", { maxlength: 2000, placeholder: "Add an analyst note (requires analyst API key)", "aria-label": "New note" });
  const noteMsg = h("p", { class: "small" });
  const noteBtn = h("button", { class: "btn", type: "button" }, "Add note");
  noteBtn.addEventListener("click", async () => {
    noteMsg.textContent = "";
    try {
      await api(`/api/threats/${encodeURIComponent(t.threat_id)}/notes`, { method: "POST", body: { note: noteText.value } });
      load();
    } catch (err) { noteMsg.className = "small error"; noteMsg.textContent = err.message; }
  });

  const statusSel = h("select", { "aria-label": "New status" }, STATUSES.map((s) => h("option", { value: s, selected: s === t.status }, titleCase(s))));
  const statusBtn = h("button", { class: "btn ghost", type: "button" }, "Update status");
  const statusMsg = h("p", { class: "small" });
  statusBtn.addEventListener("click", async () => {
    statusMsg.textContent = "";
    try {
      await api(`/api/threats/${encodeURIComponent(t.threat_id)}`, { method: "PUT", body: { status: statusSel.value } });
      load();
    } catch (err) { statusMsg.className = "small error"; statusMsg.textContent = err.message; }
  });

  const notes = card("Analyst notes & triage", "analyst role required to write",
    noteList, h("div", { class: "section", style: "margin-top:14px" }, noteText, h("div", { class: "row", style: "margin-top:8px" }, noteBtn), noteMsg),
    h("div", { class: "row", style: "margin-top:14px" }, h("span", { class: "small muted" }, "Triage decision:"), statusSel, statusBtn), statusMsg);

  root.append(h("div", { class: "grid grid-2 section" }, timeline, notes));

  const info = t.category_info || {};
  root.append(h("div", { class: "grid grid-2 section" },
    card("Recommended defensive actions", "non-destructive",
      h("ol", {}, t.recommended_actions.map((a) => h("li", {}, a))),
      h("p", { class: "small muted", style: "margin-top:8px" }, "Never visit the indicator, download files by hash, or contact the infrastructure.")),
    card(`About ${info.label || "this category"}`, null,
      h("p", {}, info.description || ""),
      kvRows([
        ["Common indicators", (info.common_indicators || []).join("; ")],
        ["Potential impact", (info.potential_impact || []).join("; ")],
        ["Defensive controls", (info.defensive_controls || []).join("; ")],
        ["Awareness", info.awareness],
      ]),
      info.awareness_module ? h("p", { style: "margin-top:10px" }, h("a", { href: "awareness.html#" + info.awareness_module }, "Open the matching awareness module →")) : null)));
}

async function load() {
  const id = qs("id");
  if (!id) { showError($("#detail"), new Error("No threat id given. Open a record from the dashboard.")); return; }
  try { render(await api("/api/threats/" + encodeURIComponent(id))); }
  catch (err) { showError($("#detail"), err); }
}

document.addEventListener("DOMContentLoaded", load);
