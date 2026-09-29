"use strict";

function list(title, items) {
  if (!items || !items.length) return null;
  return [h("h4", {}, title), h("ul", {}, items.map((x) => h("li", {}, x)))];
}

function moduleCard(m, index) {
  const body = h("div", { class: "module-body hidden" },
    h("h4", {}, "What is it?"), h("p", {}, m.what_is_it),
    h("h4", {}, "Why does it matter?"), h("p", {}, m.why_it_matters),
    list("Warning signs", m.warning_signs),
    list("Safe practices", m.safe_practices),
    list("What to do if something happens", m.what_to_do),
    (m.extra_sections || []).map((s) => list(s.title, s.items)));
  const toggle = h("button", { class: "btn ghost small", type: "button", "aria-expanded": "false" }, "Open module");
  const card = h("article", { class: "card module-card", id: m.module_id },
    h("div", { class: "row" }, h("span", { class: "module-num" }, String(index + 1).padStart(2, "0")), h("span", { class: "badge label" }, m.category)),
    h("h3", { style: "margin-top:8px" }, m.title),
    h("p", { class: "small" }, m.summary),
    toggle, body);
  const open = (state) => {
    body.classList.toggle("hidden", !state);
    card.classList.toggle("open", state);
    card.classList.toggle("span-2", state);
    toggle.textContent = state ? "Close module" : "Open module";
    toggle.setAttribute("aria-expanded", String(state));
  };
  toggle.addEventListener("click", (e) => { e.stopPropagation(); open(body.classList.contains("hidden")); });
  card.addEventListener("click", () => { if (body.classList.contains("hidden")) open(true); });
  card._open = open;
  return card;
}

document.addEventListener("DOMContentLoaded", async () => {
  const box = $("#modules");
  try {
    const data = await api("/api/awareness/modules");
    clear(box).append(...data.items.map(moduleCard));
    const target = location.hash && document.getElementById(location.hash.slice(1));
    if (target && target._open) { target._open(true); target.scrollIntoView({ block: "start" }); }
  } catch (err) { showError(box, err); }
});
