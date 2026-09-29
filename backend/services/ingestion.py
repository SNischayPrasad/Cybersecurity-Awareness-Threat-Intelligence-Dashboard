"""
Data Ingestion Pipeline
=======================

Threat data (CSV feed)
  -> Collection      (pandas reads the file)
  -> Normalisation   (trim, upper-case enums, ISO dates)
  -> Validation      (IOC syntax + field rules; bad rows are rejected, not guessed)
  -> IOC extraction  (primary indicator stored in the indicators table)
  -> Classification  (category + ATT&CK mapping when behaviour justifies it)
  -> Scoring         (confidence from feed, risk re-computed locally)
  -> Storage         (SQLite)
  -> Correlation + Alerts (see alert_engine.build_all_alerts)
"""
from __future__ import annotations

import json
from pathlib import Path

from backend.database import set_meta, utc_now
from backend.services.awareness_service import load_json, seed_synthetic_quiz_results
from backend.services.threat_service import (
    add_timeline_event,
    ensure_sources,
    insert_threat,
    normalize_threat_input,
    score_record,
)
from backend.services.vulnerability_service import calculate_vulnerability_priority, cvss_severity


def ingest_threat_csv(conn, csv_path: str) -> dict:
    import pandas as pd

    stats = {"rows_read": 0, "ingested": 0, "rejected": 0, "duplicates": 0, "rejection_samples": []}
    if not Path(csv_path).exists():
        stats["error"] = f"CSV not found: {csv_path}"
        return stats
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    stats["rows_read"] = len(df)

    records, seen = [], set()
    for row in df.to_dict("records"):
        try:
            rec = normalize_threat_input(row, require_id=True)
        except ValueError as exc:
            stats["rejected"] += 1
            if len(stats["rejection_samples"]) < 5:
                stats["rejection_samples"].append({"threat_id": row.get("threat_id"), "errors": exc.args[0]})
            continue
        if rec["threat_id"] in seen:
            stats["duplicates"] += 1
            continue
        seen.add(rec["threat_id"])
        records.append(rec)
    if not records:
        return stats

    # The dataset's own "today" = newest last_seen (keeps recency scoring reproducible).
    reference = max(r["last_seen"] for r in records)
    by_campaign, by_indicator = {}, {}
    for r in records:
        if r["campaign_id"]:
            by_campaign.setdefault(r["campaign_id"], set()).add(r["threat_id"])
        by_indicator.setdefault(r["indicator_value"].lower(), set()).add(r["threat_id"])

    sources = ensure_sources(conn)
    now = utc_now()
    for r in records:
        related = set(by_indicator[r["indicator_value"].lower()])
        if r["campaign_id"]:
            related |= by_campaign[r["campaign_id"]]
        related.discard(r["threat_id"])
        score_record(r, len(related), reference)
        insert_threat(conn, r, sources, now)
        stats["ingested"] += 1
    set_meta(conn, "dataset_reference_date", reference)
    set_meta(conn, "dataset_label", "SYNTHETIC / DEMO ONLY")
    conn.commit()
    return stats


def seed_demo_scenario(conn) -> None:
    """Extra context for the demo record (related indicator, notes, risk history)."""
    row = conn.execute("SELECT t.threat_id, t.first_seen, t.last_seen, t.risk_score FROM threats t "
                       "JOIN indicators i ON i.threat_id=t.threat_id "
                       "WHERE i.normalized_value='login-check.invalid' AND i.is_primary=1").fetchone()
    if not row:
        return
    tid = row["threat_id"]
    conn.execute("INSERT INTO indicators(threat_id, indicator_type, indicator_value, normalized_value, is_primary, "
                 "first_seen, last_seen) VALUES (?,?,?,?,0,?,?)",
                 (tid, "IP", "198.51.100.25", "198.51.100.25", row["first_seen"], row["last_seen"]))
    notes = [
        "Indicator appears in multiple synthetic phishing observations.",
        "Domain resolves (per synthetic passive-DNS note) to 198.51.100.25. Domain was NOT visited.",
        "No confirmed credential submission in synthetic proxy logs. Keeping status MONITORING.",
    ]
    for i, note in enumerate(notes):
        conn.execute("INSERT INTO analyst_notes(threat_id, author, note, created_at) VALUES (?,?,?,?)",
                     (tid, "tier1-analyst", note, f"{row['last_seen']}T0{9 + i}:00:00Z"))
    add_timeline_event(conn, tid, row["first_seen"], "RISK_ASSESSED",
                       "Initial risk 62 (HIGH) from a single vendor report.")
    from datetime import date, timedelta
    day_before = (date.fromisoformat(row["last_seen"]) - timedelta(days=1)).isoformat()
    add_timeline_event(conn, tid, max(day_before, row["first_seen"]), "RISK_INCREASED",
                       f"Risk 62 -> {row['risk_score']} after correlation with 3 related indicators "
                       "(IP, URL, sender address).")
    conn.commit()


def ingest_vulnerabilities(conn, csv_path: str) -> int:
    import pandas as pd

    if not Path(csv_path).exists():
        return 0
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    count = 0
    for v in df.to_dict("records"):
        cvss = float(v["cvss_score"])
        patch = v["patch_available"] in ("1", "True", "true")
        sensitive = v.get("handles_sensitive_data") in ("1", "True", "true")
        p = calculate_vulnerability_priority(cvss, v["asset_criticality"], v["exposure"],
                                             v["exploitation_status_demo"], sensitive, patch)
        conn.execute(
            """INSERT OR REPLACE INTO vulnerabilities(cve_id, product_category, description, severity, cvss_score,
                   published_date, patch_available, exploitation_status_demo, asset_criticality, exposure,
                   handles_sensitive_data, priority_score, priority_band) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (v["cve_id"].upper(), v["product_category"], v["description"], cvss_severity(cvss), cvss,
             v["published_date"], int(patch), v["exploitation_status_demo"], v["asset_criticality"],
             v["exposure"], int(sensitive), p["priority_score"], p["priority_band"]))
        count += 1
    conn.commit()
    return count


def load_awareness_modules(conn, awareness_dir: str) -> int:
    modules = load_json(awareness_dir, "modules.json")
    for m in modules:
        content = {k: v for k, v in m.items() if k not in ("module_id", "title", "category")}
        conn.execute("INSERT OR REPLACE INTO awareness_modules(module_id, title, category, content_json) "
                     "VALUES (?,?,?,?)", (m["module_id"], m["title"], m["category"], json.dumps(content)))
    conn.commit()
    return len(modules)


def run_full_pipeline(conn, config: dict, seed_quiz_history: bool = True) -> dict:
    """Build the whole database from the CSV files + awareness JSON."""
    from backend.services.alert_engine import build_all_alerts

    report = {"vulnerabilities": ingest_vulnerabilities(conn, config["VULN_CSV"])}
    report["threats"] = ingest_threat_csv(conn, config["THREAT_CSV"])
    seed_demo_scenario(conn)
    report["awareness_modules"] = load_awareness_modules(conn, config["AWARENESS_DIR"])
    if seed_quiz_history:
        seed_synthetic_quiz_results(conn)
        conn.commit()
    report["alerts"] = build_all_alerts(conn, config, config.get("CORRELATION_WINDOW_MINUTES", 60))
    return report
