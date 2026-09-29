"""
Alert Engine + Alert Correlation
================================

generate_threat_alert()  -> turns a scored threat record into alert candidates
generate_cluster_alert() -> one alert for a whole correlated cluster
generate_vulnerability_alert() -> alert for a high-priority vulnerability
correlate_alerts()       -> merges duplicate candidates to fight ALERT FATIGUE

Alert fatigue: when analysts get hundreds of near-identical alerts, real
signals get missed. If the same indicator is seen 100 times in 5 minutes we
raise ONE alert with observation_count = 100, not 100 alerts.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from backend.database import audit, set_meta, utc_now

ALERT_STATUSES = ("NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE")
SEVERITY_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

DEFAULT_THRESHOLDS = {
    "ALERT_RISK_THRESHOLD": 61,
    "ALERT_CONFIDENCE_THRESHOLD": 60,
    "REPEATED_OBSERVATION_THRESHOLD": 50,
    "CORRELATED_CLUSTER_MIN_SIZE": 3,
    "VULN_PRIORITY_THRESHOLD": 80,
}

THREAT_TO_ALERT_STATUS = {"NEW": "NEW", "UNDER_REVIEW": "INVESTIGATING", "MONITORING": "MONITORING",
                          "CLOSED": "RESOLVED", "FALSE_POSITIVE": "FALSE_POSITIVE"}


def _thresholds(overrides) -> dict:
    t = dict(DEFAULT_THRESHOLDS)
    for k in t:
        if overrides and overrides.get(k) is not None:
            t[k] = int(overrides[k])
    return t


def _candidate(threat, alert_type, severity, description, timestamp=None, count=1) -> dict:
    return {
        "threat_id": threat.get("threat_id"),
        "indicator_value": threat.get("indicator_value"),
        "alert_type": alert_type,
        "severity": severity,
        "risk_score": threat.get("risk_score"),
        "confidence_score": threat.get("confidence_score"),
        "description": description,
        "status": THREAT_TO_ALERT_STATUS.get(threat.get("status", "NEW"), "NEW"),
        "observation_count": count,
        "timestamp": timestamp or threat.get("timestamp") or f"{threat.get('last_seen')}T00:00:00",
    }


def generate_threat_alert(threat: dict, thresholds: dict | None = None) -> list[dict]:
    """Evaluate alert rules for ONE threat record. Returns 0..n alert candidates."""
    t = _thresholds(thresholds)
    risk, conf = int(threat["risk_score"]), int(threat["confidence_score"])
    ind = threat.get("indicator_value", "")
    alerts = []
    if risk >= 81 and conf >= 50:
        alerts.append(_candidate(threat, "CRITICAL_RISK_INDICATOR", "CRITICAL",
                                 f"Critical-risk indicator {ind} (risk {risk}, confidence {conf}). "
                                 "Triage immediately - not yet a confirmed incident."))
    elif risk >= t["ALERT_RISK_THRESHOLD"] and conf >= t["ALERT_CONFIDENCE_THRESHOLD"]:
        alerts.append(_candidate(threat, "HIGH_RISK_INDICATOR", "HIGH",
                                 f"High-risk, well-supported indicator {ind} (risk {risk}, confidence {conf})."))
    elif risk >= t["ALERT_RISK_THRESHOLD"] and conf < 40:
        alerts.append(_candidate(threat, "UNVERIFIED_HIGH_RISK", "MEDIUM",
                                 f"Indicator {ind} scores high risk ({risk}) but confidence is low ({conf}). "
                                 "Validate the intelligence before acting."))
    obs = int(threat.get("observation_count", 1))
    if obs >= t["REPEATED_OBSERVATION_THRESHOLD"]:
        sev = threat.get("severity", "MEDIUM")
        sev = sev if SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK["MEDIUM"] else "MEDIUM"
        alerts.append(_candidate(threat, "REPEATED_OBSERVATION", sev,
                                 f"Indicator {ind} observed {obs} times.", count=obs))
    return alerts


def generate_cluster_alert(cluster: dict, thresholds: dict | None = None) -> dict | None:
    """One alert per correlated cluster (not one per member)."""
    t = _thresholds(thresholds)
    if cluster["size"] < t["CORRELATED_CLUSTER_MIN_SIZE"] or cluster["max_risk"] < t["ALERT_RISK_THRESHOLD"]:
        return None
    lead = cluster["lead"]
    alert = _candidate(lead, "CORRELATED_INDICATORS", "HIGH" if cluster["max_risk"] <= 80 else "CRITICAL",
                       f"{cluster['size']} related records ({', '.join(cluster['indicator_types'])}) linked by "
                       f"{' + '.join(cluster['link_reasons'])}. Correlation is not attribution.",
                       timestamp=f"{cluster['last_seen']}T00:00:00")
    alert["indicator_value"] = cluster["cluster_key"]
    alert["related_threat_ids"] = cluster["threat_ids"]
    return alert


def generate_vulnerability_alert(vuln: dict, thresholds: dict | None = None) -> dict | None:
    t = _thresholds(thresholds)
    if float(vuln["priority_score"]) < t["VULN_PRIORITY_THRESHOLD"]:
        return None
    return {
        "threat_id": None, "vulnerability_cve": vuln["cve_id"], "indicator_value": vuln["cve_id"],
        "alert_type": "HIGH_PRIORITY_VULNERABILITY", "severity": "CRITICAL" if vuln["priority_score"] >= 90 else "HIGH",
        "risk_score": int(round(float(vuln["priority_score"]))), "confidence_score": None,
        "description": f"{vuln['cve_id']} ({vuln['product_category']}) has patch priority "
                       f"{vuln['priority_score']} ({vuln['priority_band']}).",
        "status": "NEW", "observation_count": 1, "timestamp": f"{vuln['published_date']}T00:00:00",
    }


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(str(ts).replace("Z", ""))


def correlate_alerts(alerts: list[dict], window_minutes: int = 60) -> list[dict]:
    """Merge alerts with the same (alert_type, indicator) inside a time window.

    100 identical sightings in 5 minutes -> 1 alert with observation_count=100.
    """
    window = timedelta(minutes=window_minutes)
    ordered = sorted(alerts, key=lambda a: (a["alert_type"], str(a.get("indicator_value")), _parse(a["timestamp"])))
    merged, open_groups = [], {}
    for a in ordered:
        key = (a["alert_type"], str(a.get("indicator_value")))
        ts = _parse(a["timestamp"])
        g = open_groups.get(key)
        if g and ts - _parse(g["first_observed"]) <= window:
            g["observation_count"] += a.get("observation_count", 1)
            g["last_observed"] = max(g["last_observed"], a["timestamp"])
            g["risk_score"] = max(g["risk_score"] or 0, a.get("risk_score") or 0)
            if a.get("confidence_score") is not None:
                g["confidence_score"] = max(g["confidence_score"] or 0, a["confidence_score"])
            if SEVERITY_RANK[a["severity"]] > SEVERITY_RANK[g["severity"]]:
                g["severity"] = a["severity"]
            if a.get("threat_id"):
                g["related_threat_ids"].add(a["threat_id"])
            g["merged_candidates"] += 1
            continue
        g = dict(a)
        g["first_observed"] = a["timestamp"]
        g["last_observed"] = a["timestamp"]
        g["related_threat_ids"] = set(a.get("related_threat_ids") or ([a["threat_id"]] if a.get("threat_id") else []))
        g["merged_candidates"] = 1
        open_groups[key] = g
        merged.append(g)
    for g in merged:
        g["related_threat_ids"] = sorted(g["related_threat_ids"])
        if g["merged_candidates"] > 1:
            g["description"] += (f" [Correlated: {g['merged_candidates']} alert candidates merged, "
                                 f"{g['observation_count']} observations.]")
    return merged


def simulate_observation_burst(threat: dict, count: int = 100, minutes: int = 5) -> list[dict]:
    """Synthetic sensor sightings: `count` observations of one indicator in `minutes`."""
    start = _parse(threat.get("timestamp") or f"{threat['last_seen']}T10:00:00")
    step = (minutes * 60) / max(1, count)
    return [_candidate(threat, "INDICATOR_SIGHTING", "MEDIUM",
                       f"Sensor sighting of indicator {threat['indicator_value']}.",
                       timestamp=(start + timedelta(seconds=i * step)).isoformat(timespec="seconds"))
            for i in range(count)]


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def _next_alert_number(conn) -> int:
    row = conn.execute("SELECT MAX(CAST(SUBSTR(alert_id, 5) AS INTEGER)) FROM alerts").fetchone()
    return (row[0] or 0) + 1


def store_alerts(conn, alerts: list[dict]) -> list[str]:
    n = _next_alert_number(conn)
    now = utc_now()
    ids = []
    for a in alerts:
        alert_id = f"ALR-{n:05d}"
        n += 1
        related = a.get("related_threat_ids") or ([a["threat_id"]] if a.get("threat_id") else [])
        conn.execute(
            """INSERT INTO alerts(alert_id, threat_id, vulnerability_cve, indicator_value, alert_type, severity,
                   risk_score, confidence_score, description, status, observation_count, related_threat_ids,
                   first_observed, last_observed, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (alert_id, a.get("threat_id"), a.get("vulnerability_cve"), a.get("indicator_value"), a["alert_type"],
             a["severity"], a.get("risk_score"), a.get("confidence_score"), a["description"], a["status"],
             a.get("observation_count", 1), ",".join(related), a.get("first_observed", a.get("timestamp")),
             a.get("last_observed", a.get("timestamp")), a.get("timestamp") or now, now))
        ids.append(alert_id)
    return ids


def build_all_alerts(conn, thresholds: dict | None = None, window_minutes: int = 60) -> dict:
    """Pipeline stage run by init_db: rules -> candidates -> correlation -> storage."""
    from backend.services.correlation_engine import _load_records, correlate_threats

    rows = [dict(r) for r in conn.execute(
        "SELECT t.*, i.indicator_value, i.indicator_type, t.created_at AS timestamp FROM threats t "
        "JOIN indicators i ON i.threat_id=t.threat_id AND i.is_primary=1")]
    by_id = {r["threat_id"]: r for r in rows}
    candidates = []
    for r in rows:
        candidates.extend(generate_threat_alert(r, thresholds))

    for cluster in correlate_threats(_load_records(conn), min_size=3):
        members = [by_id[t] for t in cluster["threat_ids"]]
        active = [m for m in members if m["status"] in ("NEW", "UNDER_REVIEW", "MONITORING")]
        if not active:
            continue
        cluster["lead"] = max(active, key=lambda m: m["risk_score"])
        cluster["cluster_key"] = cluster["campaign_ids"][0] if cluster["campaign_ids"] else cluster["cluster_id"]
        alert = generate_cluster_alert(cluster, thresholds)
        if alert:
            candidates.append(alert)

    for v in conn.execute("SELECT * FROM vulnerabilities"):
        alert = generate_vulnerability_alert(dict(v), thresholds)
        if alert:
            candidates.append(alert)

    # Burst demo: 100 sightings of the high-volume scanning IP in 5 minutes.
    burst = next((r for r in rows if r["indicator_value"] == "203.0.113.77"), None)
    if burst:
        candidates.extend(simulate_observation_burst(burst, 100, 5))

    correlated = correlate_alerts(candidates, window_minutes)
    store_alerts(conn, correlated)
    raw, final = len(candidates), len(correlated)
    set_meta(conn, "alert_candidates_raw", raw)
    set_meta(conn, "alerts_after_correlation", final)
    conn.commit()
    return {"raw_candidates": raw, "correlated_alerts": final,
            "reduction_percent": round(100 * (raw - final) / raw, 1) if raw else 0}


def list_alerts(conn, status=None, severity=None, alert_type=None, limit=200) -> list[dict]:
    sql = "SELECT * FROM alerts WHERE 1=1"
    args = []
    for value, col in ((status, "status"), (severity, "severity"), (alert_type, "alert_type")):
        if value:
            vals = [v.strip().upper() for v in str(value).split(",") if v.strip()]
            sql += f" AND {col} IN ({','.join('?' * len(vals))})"
            args.extend(vals)
    sql += (" ORDER BY CASE status WHEN 'NEW' THEN 0 WHEN 'INVESTIGATING' THEN 1 WHEN 'MONITORING' THEN 2 "
            "ELSE 3 END, CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, "
            "created_at DESC LIMIT ?")
    args.append(max(1, min(1000, int(limit))))
    return [dict(r) for r in conn.execute(sql, args)]


def alert_summary(conn) -> dict:
    from backend.database import get_meta

    return {
        "by_status": {r[0]: r[1] for r in conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")},
        "by_type": {r[0]: r[1] for r in conn.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type")},
        "by_severity": {r[0]: r[1] for r in conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")},
        "raw_candidates": int(get_meta(conn, "alert_candidates_raw", 0)),
        "after_correlation": int(get_meta(conn, "alerts_after_correlation", 0)),
    }


def update_alert_status(conn, alert_id: str, status: str, role: str, comment: str = "") -> dict | None:
    status = (status or "").upper()
    if status not in ALERT_STATUSES:
        raise ValueError([f"status must be one of {', '.join(ALERT_STATUSES)}."])
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id.upper(),)).fetchone()
    if not row:
        return None
    conn.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
                 (status, utc_now(), alert_id.upper()))
    audit(conn, role, "UPDATE_ALERT_STATUS", alert_id.upper(), f"{row['status']} -> {status}. {comment}"[:500])
    conn.commit()
    return dict(conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id.upper(),)).fetchone())
