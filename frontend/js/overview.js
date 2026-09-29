"use strict";

document.addEventListener("DOMContentLoaded", async () => {
  $("#quick-search").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = $("#quick-q").value.trim();
    if (q) location.href = "threat-dashboard.html?q=" + encodeURIComponent(q) + "#ioc-search";
  });

  const tiles = [
    ["threat-dashboard.html", "SOC Dashboard", "KPIs, 10 charts, IOC search, filterable threat table."],
    ["attack.html", "MITRE ATT&CK", "Tactics and techniques - mapped only when behaviour justifies it."],
    ["vulnerabilities.html", "Vulnerabilities", "CVSS + asset + exposure + exploitation = contextual priority."],
    ["alerts.html", "Alert Queue", "Correlated alerts, SOC workflow, triage statuses."],
    ["awareness.html", "Awareness Center", "15 modules: phishing, MFA, ransomware, AI scams and more."],
    ["quiz.html", "Security Quiz", "40 questions, category scores and learning recommendations."],
    ["executive.html", "Executive Summary", "Plain-language view for non-technical leaders."],
    ["threat-details.html?id=THR-2026-001", "Demo investigation", "Synthetic Credential Phishing Campaign (THR-…-001)."],
  ];
  const box = $("#tiles");
  tiles.forEach(([href, title, text]) => box.append(
    h("a", { class: "card", href, style: "display:block" }, h("h3", {}, title), h("p", { class: "small" }, text))));

  try {
    const s = await api("/api/dashboard/stats");
    const l = s.evidence_ladder;
    $("#l-obs").textContent = fmt(l.observations);
    $("#l-ind").textContent = fmt(l.indicators);
    $("#l-alert").textContent = fmt(l.alerts);
    $("#l-threat").textContent = fmt(l.threats);
    $("#l-inc").textContent = fmt(l.incidents);
    // Demo tile should point at the real demo ID for the dataset's year.
    const health = await api("/api/health");
    const year = (health.dataset_reference_date || "").slice(0, 4);
    const demo = box.querySelector('a[href^="threat-details.html"]');
    if (year && demo) demo.setAttribute("href", `threat-details.html?id=THR-${year}-001`);
  } catch (err) {
    $("#ladder").after(h("p", { class: "error" }, "Could not load stats: " + err.message +
      " — did you run `python -m backend.init_db`?"));
  }
});
