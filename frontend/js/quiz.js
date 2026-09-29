"use strict";

let QUESTIONS = [];

function answers() {
  const out = {};
  QUESTIONS.forEach((q) => {
    const checked = document.querySelector(`input[name="${q.id}"]:checked`);
    if (checked) out[q.id] = checked.value;
  });
  return out;
}

function updateProgress() {
  $("#progress").textContent = `${Object.keys(answers()).length} / ${QUESTIONS.length} answered`;
}

function renderQuestions() {
  const form = clear($("#quiz"));
  QUESTIONS.forEach((q, i) => {
    form.append(h("fieldset", { class: "q", id: "q-" + q.id, style: "margin:0" },
      h("legend", { class: "q-head", style: "padding:0" }, h("span", { class: "qid" }, `${i + 1}.`), h("span", { class: "badge label" }, q.category)),
      h("p", { style: "color:var(--ink);font-weight:600" }, q.question),
      Object.entries(q.options).map(([letter, text]) => h("label", { class: "opt" },
        h("input", { type: "radio", name: q.id, value: letter, onchange: updateProgress }),
        h("span", {}, h("strong", {}, letter + ". "), text))),
      h("div", { class: "feedback small" })));
  });
  updateProgress();
}

function bar(label, value) {
  return h("div", { class: "bar-row" }, h("span", {}, label),
    h("div", { class: "track" }, h("div", { class: "fill", style: `width:${value}%` })), h("span", { class: "num" }, `${value}%`));
}

function renderResult(r) {
  const box = clear($("#result"));
  box.classList.remove("hidden");
  box.append(h("div", { class: "grid grid-3" },
    h("div", { class: "card" }, h("div", { class: "card-sub" }, "Overall awareness score"),
      h("div", { class: "score-hero" }, r.overall_score, h("span", { class: "muted", style: "font-size:20px" }, " / 100")),
      h("div", { class: "badge label", style: "margin-top:8px" }, r.band),
      h("p", { class: "small", style: "margin-top:8px" }, `${r.correct} of ${r.total_questions} correct · ${r.answered} answered`),
      h("p", { class: "small muted" }, "0–40 Needs Improvement · 41–60 Basic · 61–80 Good · 81–100 Strong")),
    h("div", { class: "card" }, h("h3", {}, "Category scores"),
      Object.entries(r.category_scores).sort((a, b) => a[1] - b[1]).map(([c, s]) => bar(c, s))),
    h("div", { class: "card" }, h("h3", {}, "Weakest areas"),
      r.weakest_areas.length ? h("ul", {}, r.weakest_areas.map((w) => h("li", {}, `${w.category}: ${w.score}%`))) : h("p", {}, "No weak areas below 80% — great work."),
      h("h3", { style: "margin-top:14px" }, "Recommended learning"),
      h("ul", {}, r.recommendations.filter((x) => x.action !== "None").map((x) =>
        h("li", {}, h("strong", {}, `${x.category} (${x.score}%): `), x.recommendation, " ",
          x.module_id ? h("a", { href: "awareness.html#" + x.module_id }, "Open →") : null))),
      r.recommendations.every((x) => x.action === "None") ? h("p", {}, "No immediate module required.") : null)));
  box.append(h("p", { class: "small muted", style: "margin:10px 0 20px" }, r.disclaimer));

  r.feedback.forEach((f) => {
    const q = document.getElementById("q-" + f.id);
    if (!q) return;
    q.classList.add(f.correct ? "correct" : "wrong");
    const fb = q.querySelector(".feedback");
    clear(fb).append(h("p", { class: f.correct ? "success" : "error", style: "margin:8px 0 2px" },
      f.correct ? "Correct." : `Incorrect${f.your_answer ? "" : " (unanswered)"} — correct answer: ${f.correct_answer}.`),
      h("p", {}, f.explanation));
  });
  box.scrollIntoView({ behavior: "smooth" });
}

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const data = await api("/api/quiz");
    QUESTIONS = data.questions;
    $("#disclaimer").textContent = data.disclaimer;
    renderQuestions();
  } catch (err) { showError($("#quiz"), err); }

  $("#submit").addEventListener("click", async () => {
    const a = answers();
    const msg = $("#submit-msg");
    if (!Object.keys(a).length) { msg.className = "small error"; msg.textContent = "Answer at least one question first."; return; }
    if (Object.keys(a).length < QUESTIONS.length &&
        !confirm(`You answered ${Object.keys(a).length} of ${QUESTIONS.length}. Unanswered questions count as incorrect. Submit anyway?`)) return;
    try {
      const r = await api("/api/quiz/submit", { method: "POST", body: { answers: a } });
      msg.textContent = "";
      renderResult(r);
      $("#submit").disabled = true;
    } catch (err) { msg.className = "small error"; msg.textContent = err.message; }
  });
});
