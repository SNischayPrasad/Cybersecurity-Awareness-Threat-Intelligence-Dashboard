"""
Executive Cybersecurity Summary
===============================

Translates SOC data into plain language for non-technical leaders:
what is the threat picture, how exposed are we, how aware are our people,
and what should we prioritise next.
"""
from __future__ import annotations

from backend.services.alert_engine import alert_summary
from backend.services.awareness_service import awareness_trend
from backend.services.threat_categories import THREAT_CATEGORIES
from backend.services.threat_service import ACTIVE_STATUSES


def build_executive_summary(conn) -> dict:
    one = lambda sql, p=(): conn.execute(sql, p).fetchone()[0]  # noqa: E731
    active = ",".join(f"'{s}'" for s in ACTIVE_STATUSES)
    total = one("SELECT COUNT(*) FROM threats")
    crit = one(f"SELECT COUNT(*) FROM threats WHERE severity='CRITICAL' AND status IN ({active})")
    high = one(f"SELECT COUNT(*) FROM threats WHERE severity='HIGH' AND status IN ({active})")
    active_total = one(f"SELECT COUNT(*) FROM threats WHERE status IN ({active})")
    top_cats = [dict(r) for r in conn.execute(
        f"SELECT category, COUNT(*) AS count FROM threats WHERE status IN ({active}) "
        f"GROUP BY category ORDER BY count DESC LIMIT 5")]
    for c in top_cats:
        c["label"] = THREAT_CATEGORIES[c["category"]]["label"]
    top_vuln_products = [dict(r) for r in conn.execute(
        "SELECT product_category, COUNT(*) AS count, SUM(priority_band='P1') AS p1 FROM vulnerabilities "
        "GROUP BY product_category ORDER BY p1 DESC, count DESC LIMIT 5")]
    p1 = one("SELECT COUNT(*) FROM vulnerabilities WHERE priority_band='P1'")
    alerts = alert_summary(conn)
    awareness = awareness_trend(conn)

    avg_now = awareness["average_scores"][-1] if awareness["average_scores"] else None
    avg_then = awareness["average_scores"][0] if awareness["average_scores"] else None

    headline = (f"We are tracking {total:,} synthetic threat records; {active_total:,} are still active. "
                f"{crit} critical and {high} high-severity items need attention. "
                f"No security incident has been confirmed.")
    if total == 0:
        headline = "No threat intelligence has been loaded yet."

    priorities = []
    if crit + high:
        priorities.append(f"Triage the {crit + high} active critical/high threat records within service targets.")
    if p1:
        priorities.append(f"Patch or mitigate {p1} P1 vulnerabilities (internet-facing or actively exploited first).")
    if top_cats:
        lead = top_cats[0]["label"]
        priorities.append(f"{lead} is the most common active threat type - reinforce matching controls and training.")
    if awareness["weakest"]:
        w = ", ".join(c for c, _ in awareness["weakest"][:2])
        priorities.append(f"Target awareness training at the weakest areas: {w}.")
    priorities.append("Keep phishing-resistant MFA and tested offline backups as baseline controls.")

    return {
        "headline": headline,
        "threat_landscape": {
            "total_records": total, "active_records": active_total,
            "critical_active": crit, "high_active": high, "confirmed_incidents": 0,
            "open_alerts": alerts["by_status"].get("NEW", 0) + alerts["by_status"].get("INVESTIGATING", 0),
        },
        "top_threat_categories": top_cats,
        "top_vulnerability_categories": top_vuln_products,
        "p1_vulnerabilities": p1,
        "alert_noise_reduction": {
            "raw_candidates": alerts["raw_candidates"], "after_correlation": alerts["after_correlation"]},
        "awareness": {
            "months": awareness["months"], "average_scores": awareness["average_scores"],
            "current_average": avg_now, "starting_average": avg_then,
            "top_weaknesses": [{"category": c, "average": s} for c, s in awareness["weakest"]],
        },
        "recommended_priorities": priorities,
        "plain_language_notes": [
            "Risk score = how concerning something could be. Confidence = how sure we are about the information.",
            "An indicator on a threat feed is a lead, not proof that we were attacked.",
            "All data in this dashboard is synthetic and for demonstration only.",
        ],
    }
