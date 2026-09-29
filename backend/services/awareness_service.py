"""
Awareness Center, Quiz Engine, Awareness Score and Learning Recommendations.

The awareness score is an EDUCATIONAL indicator for self-improvement.
It is NOT an employee performance, fitness or competency judgement.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from backend.database import utc_now

QUIZ_CATEGORY_TO_MODULE = {
    "Phishing": "phishing",
    "Passwords": "password-security",
    "MFA": "mfa",
    "Social Engineering": "social-engineering",
    "Safe Browsing": "safe-browsing",
    "Ransomware": "ransomware",
    "Privacy": "data-privacy",
    "Wi-Fi": "secure-wifi",
    "Mobile Security": "mobile-security",
    "Incident Reporting": "incident-reporting",
}

SCORE_BANDS = [(81, "Strong Awareness"), (61, "Good Awareness"), (41, "Basic Awareness"), (0, "Needs Improvement")]
DISCLAIMER = ("Educational score only - it is not an employee fitness, performance or competency judgement. "
              "Results are stored anonymously.")


def load_json(directory: str, filename: str):
    return json.loads((Path(directory) / filename).read_text(encoding="utf-8"))


def awareness_band(score: float) -> str:
    return next(label for threshold, label in SCORE_BANDS if score >= threshold)


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------
def list_modules(conn) -> list[dict]:
    rows = conn.execute("SELECT module_id, title, category, content_json FROM awareness_modules "
                        "ORDER BY rowid").fetchall()
    out = []
    for r in rows:
        content = json.loads(r["content_json"])
        out.append({"module_id": r["module_id"], "title": r["title"], "category": r["category"], **content})
    return out


def get_module(conn, module_id: str) -> dict | None:
    r = conn.execute("SELECT module_id, title, category, content_json FROM awareness_modules WHERE module_id=?",
                     (module_id,)).fetchone()
    if not r:
        return None
    return {"module_id": r["module_id"], "title": r["title"], "category": r["category"],
            **json.loads(r["content_json"])}


# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------
def public_questions(questions: list[dict], shuffle: bool = False, seed: int | None = None) -> list[dict]:
    """Strip answers/explanations before sending questions to the browser."""
    qs = [{"id": q["id"], "category": q["category"], "question": q["question"], "options": q["options"]}
          for q in questions]
    if shuffle:
        random.Random(seed).shuffle(qs)
    return qs


def score_quiz(questions: list[dict], answers: dict) -> dict:
    """Score submitted answers {question_id: "A".."D"} -> overall + per-category results."""
    if not isinstance(answers, dict) or not answers:
        raise ValueError(["answers must be a non-empty object of {question_id: option_letter}."])
    by_id = {q["id"]: q for q in questions}
    unknown = [k for k in answers if k not in by_id]
    if unknown:
        raise ValueError([f"Unknown question id(s): {', '.join(map(str, unknown[:5]))}"])

    per_cat, feedback, correct_total = {}, [], 0
    for q in questions:
        cat = per_cat.setdefault(q["category"], {"correct": 0, "total": 0})
        cat["total"] += 1
        given = str(answers.get(q["id"], "")).strip().upper()
        ok = given == q["answer"]
        if ok:
            cat["correct"] += 1
            correct_total += 1
        feedback.append({"id": q["id"], "category": q["category"], "question": q["question"],
                         "your_answer": given or None, "correct_answer": q["answer"],
                         "correct": ok, "explanation": q["explanation"]})
    overall = round(100 * correct_total / len(questions))
    category_scores = {c: round(100 * v["correct"] / v["total"]) for c, v in per_cat.items()}
    weakest = sorted(category_scores.items(), key=lambda kv: kv[1])[:3]
    return {
        "overall_score": overall,
        "band": awareness_band(overall),
        "correct": correct_total,
        "total_questions": len(questions),
        "answered": sum(1 for q in questions if answers.get(q["id"])),
        "category_scores": category_scores,
        "weakest_areas": [{"category": c, "score": s} for c, s in weakest if s < 80],
        "recommendations": generate_learning_recommendations(category_scores),
        "feedback": feedback,
        "disclaimer": DISCLAIMER,
    }


def generate_learning_recommendations(category_scores: dict) -> list[dict]:
    """<50% -> complete the module, 50-79% -> review it, >=80% -> no module needed."""
    recs = []
    for category, score in sorted(category_scores.items(), key=lambda kv: kv[1]):
        module_id = QUIZ_CATEGORY_TO_MODULE.get(category)
        if score < 50:
            action, priority = "Complete", "HIGH"
            text = f"Complete the {category} awareness module."
        elif score < 80:
            action, priority = "Review", "MEDIUM"
            text = f"Review the {category} awareness module."
        else:
            action, priority = "None", "LOW"
            text = "No immediate module required."
        recs.append({"category": category, "score": score, "action": action, "priority": priority,
                     "module_id": module_id, "recommendation": text})
    return recs


def save_quiz_result(conn, result: dict, anonymous_id: str | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO quiz_results(anonymous_user_id_optional, overall_score, band, category_scores_json, "
        "is_synthetic, created_at) VALUES (?,?,?,?,0,?)",
        (anonymous_id, result["overall_score"], result["band"], json.dumps(result["category_scores"]), utc_now()))
    conn.commit()
    return cur.lastrowid


def awareness_trend(conn) -> dict:
    rows = conn.execute(
        "SELECT SUBSTR(created_at, 1, 7) AS month, ROUND(AVG(overall_score), 1) AS avg_score, COUNT(*) AS n "
        "FROM quiz_results GROUP BY month ORDER BY month").fetchall()
    cats = {}
    for (js,) in conn.execute("SELECT category_scores_json FROM quiz_results"):
        for c, s in json.loads(js or "{}").items():
            cats.setdefault(c, []).append(s)
    averages = {c: round(sum(v) / len(v), 1) for c, v in cats.items()}
    return {"months": [r["month"] for r in rows], "average_scores": [r["avg_score"] for r in rows],
            "attempts": [r["n"] for r in rows], "category_averages": averages,
            "weakest": sorted(averages.items(), key=lambda kv: kv[1])[:3]}


def seed_synthetic_quiz_results(conn, months: int = 6, per_month: int = 12, seed: int = 7) -> None:
    """Synthetic, anonymous history so the executive trend chart has data."""
    from datetime import date

    rng = random.Random(seed)
    today = date.today()
    cats = list(QUIZ_CATEGORY_TO_MODULE)
    weakness = {"Social Engineering": -18, "Phishing": -10, "Mobile Security": -12, "Wi-Fi": -6}
    for m in range(months, 0, -1):
        y, mo = today.year, today.month - m + 1
        while mo <= 0:
            mo += 12
            y -= 1
        improvement = (months - m) * 3  # awareness improves as training runs
        for i in range(per_month):
            scores = {c: max(0, min(100, int(rng.gauss(64 + improvement + weakness.get(c, 0), 14)))) for c in cats}
            scores = {c: round(s / 25) * 25 for c, s in scores.items()}  # 4 questions per category
            overall = round(sum(scores.values()) / len(scores))
            conn.execute("INSERT INTO quiz_results(anonymous_user_id_optional, overall_score, band, "
                         "category_scores_json, is_synthetic, created_at) VALUES (?,?,?,?,1,?)",
                         (f"anon-demo-{m}-{i}", overall, awareness_band(overall), json.dumps(scores),
                          f"{y:04d}-{mo:02d}-{rng.randint(1, 28):02d}T12:00:00Z"))
