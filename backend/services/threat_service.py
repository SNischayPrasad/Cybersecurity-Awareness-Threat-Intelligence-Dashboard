"""
Threat Service
==============

Normalisation, storage, querying and lifecycle updates for threat records.
Routes stay thin; the business logic lives here so it can be unit-tested.
"""
from __future__ import annotations

import json
from datetime import date, datetime

from backend.database import audit, utc_now
from backend.services.attack_mapper import attack_technique_url, map_to_attack, mapping_explanation
from backend.services.ioc_validator import INDICATOR_TYPES, defang, validate_indicator
from backend.services.risk_engine import (
    INTEL_SOURCES,
    RELIABILITY_LEVELS,
    SEVERITY_LEVELS,
    calculate_confidence,
    calculate_threat_risk,
    get_source_reliability,
    interpret_risk_confidence,
)
from backend.services.threat_categories import CATEGORY_CODES, THREAT_CATEGORIES, recommended_actions
from backend.utils.security import sanitize_text

THREAT_STATUSES = ("NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE")
ACTIVE_STATUSES = ("NEW", "UNDER_REVIEW", "MONITORING")

SORT_OPTIONS = {
    "newest": "t.last_seen DESC, t.threat_id DESC",
    "oldest": "t.last_seen ASC, t.threat_id ASC",
    "risk": "t.risk_score DESC, t.confidence_score DESC",
    "confidence": "t.confidence_score DESC, t.risk_score DESC",
    "observed": "t.observation_count DESC, t.risk_score DESC",
}

THREAT_SELECT = """
SELECT t.*, i.indicator_type, i.indicator_value, s.source_name, s.reliability AS source_reliability
FROM threats t
LEFT JOIN indicators i ON i.threat_id = t.threat_id AND i.is_primary = 1
LEFT JOIN sources s ON s.source_id = t.source_id
"""


# ---------------------------------------------------------------------------
# Normalisation & validation (pipeline stages 2-4)
# ---------------------------------------------------------------------------
def _norm_date(value, field: str, errors: list) -> str | None:
    if value in (None, ""):
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "")).date().isoformat()
    except ValueError:
        errors.append(f"{field} must be an ISO date (YYYY-MM-DD).")
        return None


def normalize_threat_input(raw: dict, require_id: bool = False) -> dict:
    """Clean + validate one threat record. Raises ValueError(list_of_errors)."""
    errors = []
    rec = {}
    get = lambda k, d="": raw.get(k, d) if raw.get(k) is not None else d  # noqa: E731

    rec["threat_id"] = sanitize_text(get("threat_id"), 40).upper() or None
    if require_id and not rec["threat_id"]:
        errors.append("threat_id is required.")
    rec["threat_name"] = sanitize_text(get("threat_name"), 200)
    if not rec["threat_name"]:
        errors.append("threat_name is required.")

    category = str(get("threat_category") or get("category")).strip().upper().replace(" ", "_")
    if category not in CATEGORY_CODES:
        errors.append(f"threat_category must be one of {', '.join(CATEGORY_CODES)}.")
    rec["category"] = category

    itype = str(get("indicator_type")).strip().upper().replace(" ", "_") or None
    if itype and itype not in INDICATOR_TYPES:
        errors.append(f"indicator_type must be one of {', '.join(INDICATOR_TYPES)}.")
        itype = None
    check = validate_indicator(str(get("indicator_value")), itype)
    if not check["valid"]:
        errors.append("indicator_value is not valid: " + " ".join(check["validation_notes"]))
    rec["indicator_type"] = check["indicator_type"]
    rec["indicator_value"] = check["normalized_value"]

    source = sanitize_text(get("source_name", "Unknown Source"), 60) or "Unknown Source"
    rec["source_name"] = source if source in INTEL_SOURCES else "Unknown Source"

    impact = str(get("impact_level") or get("severity") or "MEDIUM").strip().upper()
    if impact not in SEVERITY_LEVELS:
        errors.append(f"severity/impact_level must be one of {', '.join(SEVERITY_LEVELS)}.")
    rec["impact_level"] = impact

    status = str(get("status", "NEW")).strip().upper() or "NEW"
    if status not in THREAT_STATUSES:
        errors.append(f"status must be one of {', '.join(THREAT_STATUSES)}.")
    rec["status"] = status

    today = date.today().isoformat()
    rec["first_seen"] = _norm_date(get("first_seen"), "first_seen", errors) or today
    rec["last_seen"] = _norm_date(get("last_seen"), "last_seen", errors) or rec["first_seen"]
    if rec["last_seen"] < rec["first_seen"]:
        errors.append("last_seen cannot be earlier than first_seen.")

    try:
        rec["observation_count"] = max(1, min(1_000_000, int(float(get("observation_count", 1) or 1))))
    except (TypeError, ValueError):
        errors.append("observation_count must be a whole number.")
        rec["observation_count"] = 1

    conf = get("confidence_score", "")
    if conf != "":
        try:
            rec["confidence_score"] = int(float(conf))
            if not 0 <= rec["confidence_score"] <= 100:
                errors.append("confidence_score must be between 0 and 100.")
        except (TypeError, ValueError):
            errors.append("confidence_score must be a number.")
    rec["campaign_id"] = sanitize_text(get("campaign_id"), 40) or None
    rec["region"] = sanitize_text(get("country_or_region_optional") or get("region"), 60) or None
    rec["description"] = sanitize_text(get("description"), 2000)
    rec["behavior_observed"] = sanitize_text(get("behavior_observed"), 60).lower() or "reputation_only"
    cve = sanitize_text(get("cve_id_optional") or get("cve_id"), 30).upper()
    if cve:
        cve_check = validate_indicator(cve, "CVE")
        if not cve_check["valid"]:
            errors.append("cve_id is not a valid CVE ID format.")
    rec["cve_id"] = cve or None
    rec["timestamp"] = str(get("timestamp") or f"{rec['last_seen']}T00:00:00")
    if errors:
        raise ValueError(errors)
    return rec


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------
def ensure_sources(conn) -> dict:
    """Insert the known intelligence sources (idempotent). Returns name -> id."""
    for name, meta in INTEL_SOURCES.items():
        conn.execute("INSERT OR IGNORE INTO sources(source_name, source_type, reliability, description) "
                     "VALUES (?,?,?,?)", (name, meta["type"], meta["reliability"], meta["description"]))
    return {r["source_name"]: r["source_id"] for r in conn.execute("SELECT * FROM sources")}


def add_timeline_event(conn, threat_id: str, event_time: str, event_type: str, detail: str) -> None:
    conn.execute("INSERT INTO threat_timeline(threat_id, event_time, event_type, detail) VALUES (?,?,?,?)",
                 (threat_id, event_time, event_type, detail))


def initial_timeline(rec: dict) -> list[tuple]:
    """Lifecycle events derived from a record's dates and status."""
    grade = get_source_reliability(rec["source_name"])["reliability"]
    events = [(rec["first_seen"], "FIRST_SEEN", f"First observed via {rec['source_name']} (reliability {grade}).")]
    if rec["observation_count"] > 1:
        events.append((rec["last_seen"], "NEW_OBSERVATIONS",
                       f"{rec['observation_count']} total observations recorded."))
    events.append((rec["last_seen"], "RISK_ASSESSED",
                   f"Risk {rec['risk_score']} ({rec['severity']}), confidence {rec['confidence_score']}."))
    status = rec["status"]
    if status != "NEW":
        events.append((rec["last_seen"], "INVESTIGATION_STARTED", "Analyst triage started."))
    if status in ("MONITORING", "CLOSED", "FALSE_POSITIVE"):
        events.append((rec["last_seen"], status, {
            "MONITORING": "Placed under monitoring for related activity.",
            "CLOSED": "Closed - no further action required.",
            "FALSE_POSITIVE": "Marked as false positive after review.",
        }[status]))
    return events


def insert_threat(conn, rec: dict, source_ids: dict, now: str | None = None) -> None:
    """Write one normalised + scored record into threats/indicators/attack_mappings/timeline."""
    now = now or utc_now()
    conn.execute(
        """INSERT INTO threats(threat_id, threat_name, category, description, severity, impact_level,
               risk_score, confidence_score, status, first_seen, last_seen, observation_count, campaign_id,
               region, behavior_observed, cve_id, source_id, risk_breakdown_json, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rec["threat_id"], rec["threat_name"], rec["category"], rec["description"], rec["severity"],
         rec["impact_level"], rec["risk_score"], rec["confidence_score"], rec["status"], rec["first_seen"],
         rec["last_seen"], rec["observation_count"], rec["campaign_id"], rec["region"],
         rec["behavior_observed"], rec["cve_id"], source_ids.get(rec["source_name"]),
         json.dumps(rec.get("risk_breakdown", {})), rec.get("timestamp", now), now))
    conn.execute(
        "INSERT INTO indicators(threat_id, indicator_type, indicator_value, normalized_value, is_primary, "
        "first_seen, last_seen) VALUES (?,?,?,?,1,?,?)",
        (rec["threat_id"], rec["indicator_type"], rec["indicator_value"], rec["indicator_value"].lower(),
         rec["first_seen"], rec["last_seen"]))
    mapping = map_to_attack(rec["behavior_observed"])
    if mapping:
        conn.execute("INSERT INTO attack_mappings(threat_id, tactic, technique, technique_id_optional, "
                     "mapping_basis) VALUES (?,?,?,?,?)",
                     (rec["threat_id"], mapping["tactic"], mapping["technique"],
                      mapping["technique_id_optional"], mapping["mapping_basis"]))
    for when, etype, detail in initial_timeline(rec):
        add_timeline_event(conn, rec["threat_id"], when, etype, detail)


def score_record(rec: dict, correlated: int, reference_date, corroborating: int = 0,
                 analyst_verified: bool = False, related_alerts: int = 0) -> dict:
    """Pipeline stage: confidence (if not supplied) + risk + severity band."""
    src = get_source_reliability(rec["source_name"])
    if rec.get("confidence_score") is None:
        from backend.services.risk_engine import days_since
        rec["confidence_score"] = calculate_confidence(
            src["reliability"], corroborating, True, rec["behavior_observed"] != "reputation_only",
            analyst_verified, days_since(rec["last_seen"], reference_date))
    risk = calculate_threat_risk(
        rec["impact_level"], rec["confidence_score"], rec["last_seen"], rec["observation_count"],
        src["reliability"], related_alerts, min(5, correlated), map_to_attack(rec["behavior_observed"]) is not None,
        bool(rec["cve_id"]), reference_date)
    rec["risk_score"] = risk["risk_score"]
    rec["severity"] = risk["classification"]
    rec["risk_breakdown"] = {"components": risk["components"], "weighted": risk["weighted_components"],
                             "reference_date": str(reference_date or date.today())}
    return rec


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
def _csv_list(value) -> list[str]:
    if not value:
        return []
    return [v.strip().upper() for v in str(value).split(",") if v.strip()]


def list_threats(conn, params: dict) -> dict:
    """Filtered, sorted, paginated list of threats for the SOC table."""
    where, args = ["1=1"], []
    for field, column in (("severity", "t.severity"), ("category", "t.category"),
                          ("status", "t.status"), ("indicator_type", "i.indicator_type")):
        values = _csv_list(params.get(field))
        if values:
            where.append(f"{column} IN ({','.join('?' * len(values))})")
            args.extend(values)
    for field, column, op in (("min_risk", "t.risk_score", ">="), ("max_risk", "t.risk_score", "<="),
                              ("min_confidence", "t.confidence_score", ">="),
                              ("max_confidence", "t.confidence_score", "<=")):
        if params.get(field) not in (None, ""):
            try:
                args.append(int(params[field]))
                where.append(f"{column} {op} ?")
            except ValueError:
                raise ValueError([f"{field} must be an integer."])
    if params.get("date_from"):
        where.append("t.last_seen >= ?")
        args.append(str(params["date_from"])[:10])
    if params.get("date_to"):
        where.append("t.last_seen <= ?")
        args.append(str(params["date_to"])[:10])
    if params.get("campaign_id"):
        where.append("t.campaign_id = ?")
        args.append(params["campaign_id"])
    if params.get("technique_id"):
        where.append("EXISTS (SELECT 1 FROM attack_mappings m WHERE m.threat_id = t.threat_id "
                     "AND m.technique_id_optional = ?)")
        args.append(params["technique_id"].upper())
    if params.get("tactic"):
        where.append("EXISTS (SELECT 1 FROM attack_mappings m WHERE m.threat_id = t.threat_id AND m.tactic = ?)")
        args.append(params["tactic"])
    if params.get("q"):
        q = f"%{str(params['q'])[:100].lower()}%"
        where.append("(LOWER(t.threat_name) LIKE ? OR LOWER(i.indicator_value) LIKE ? OR LOWER(t.threat_id) LIKE ?)")
        args.extend([q, q, q])

    sort = SORT_OPTIONS.get(str(params.get("sort", "newest")).lower(), SORT_OPTIONS["newest"])
    try:
        page = max(1, int(params.get("page", 1)))
        page_size = max(1, min(100, int(params.get("page_size", 25))))
    except ValueError:
        raise ValueError(["page and page_size must be integers."])

    base = f"{THREAT_SELECT} WHERE {' AND '.join(where)}"
    total = conn.execute(f"SELECT COUNT(*) FROM ({base})", args).fetchone()[0]
    rows = conn.execute(f"{base} ORDER BY {sort} LIMIT ? OFFSET ?",
                        args + [page_size, (page - 1) * page_size]).fetchall()
    items = [_threat_summary(r) for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}


def _threat_summary(row) -> dict:
    d = dict(row)
    d.pop("risk_breakdown_json", None)
    d["indicator_defanged"] = defang(d.get("indicator_value") or "")
    d["category_label"] = THREAT_CATEGORIES.get(d["category"], {}).get("label", d["category"])
    return d


def get_threat(conn, threat_id: str) -> dict | None:
    row = conn.execute(f"{THREAT_SELECT} WHERE t.threat_id = ?", (threat_id.upper(),)).fetchone()
    return _threat_summary(row) if row else None


def get_threat_detail(conn, threat_id: str) -> dict | None:
    """Everything the investigation view needs, in one response."""
    from backend.services.correlation_engine import find_related_threats

    threat = get_threat(conn, threat_id)
    if not threat:
        return None
    tid = threat["threat_id"]
    raw = conn.execute("SELECT risk_breakdown_json FROM threats WHERE threat_id=?", (tid,)).fetchone()[0]
    threat["risk_breakdown"] = json.loads(raw or "{}")
    threat["source"] = get_source_reliability(threat.get("source_name") or "Unknown Source")
    threat["indicators"] = [dict(r, defanged=defang(r["indicator_value"])) for r in conn.execute(
        "SELECT indicator_id, indicator_type, indicator_value, is_primary, first_seen, last_seen "
        "FROM indicators WHERE threat_id=? ORDER BY is_primary DESC, indicator_id", (tid,))]
    mappings = [dict(r) for r in conn.execute(
        "SELECT tactic, technique, technique_id_optional, mapping_basis FROM attack_mappings WHERE threat_id=?",
        (tid,))]
    for m in mappings:
        m["reference_url"] = attack_technique_url(m["technique_id_optional"])
    threat["attack_mappings"] = mappings
    threat["attack_mapping_note"] = (mapping_explanation(threat["behavior_observed"]) if mappings else
                                     "No ATT&CK mapping: " + mapping_explanation(threat["behavior_observed"]))
    threat["related_threats"] = find_related_threats(conn, tid)
    threat["related_alerts"] = [dict(r) for r in conn.execute(
        "SELECT alert_id, alert_type, severity, status, observation_count, created_at FROM alerts "
        "WHERE threat_id = ? OR related_threat_ids LIKE ? ORDER BY created_at DESC", (tid, f"%{tid}%"))]
    threat["analyst_notes"] = [dict(r) for r in conn.execute(
        "SELECT note_id, author, note, created_at FROM analyst_notes WHERE threat_id=? ORDER BY note_id DESC",
        (tid,))]
    threat["timeline"] = [dict(r) for r in conn.execute(
        "SELECT event_time, event_type, detail FROM threat_timeline WHERE threat_id=? "
        "ORDER BY event_time, event_id", (tid,))]
    threat["vulnerability"] = None
    if threat.get("cve_id"):
        v = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id=?", (threat["cve_id"],)).fetchone()
        threat["vulnerability"] = dict(v) if v else None
    threat["interpretation"] = interpret_risk_confidence(threat["risk_score"], threat["confidence_score"])
    threat["recommended_actions"] = recommended_actions(threat["category"], threat["status"],
                                                        threat.get("indicator_type") or "")
    threat["category_info"] = THREAT_CATEGORIES.get(threat["category"])
    threat["evidence_level"] = evidence_level(threat)
    return threat


def evidence_level(threat: dict) -> dict:
    """Where this record sits on the Observation -> Incident ladder."""
    if threat["status"] == "FALSE_POSITIVE":
        return {"level": "INDICATOR", "explanation": "Reviewed and judged a false positive."}
    if threat["status"] in ("UNDER_REVIEW", "MONITORING") and threat["risk_score"] >= 61:
        return {"level": "THREAT",
                "explanation": "Credible, relevant threat under analyst review. Not a confirmed incident - "
                               "an incident requires confirmed impact on our (synthetic) environment."}
    if threat["risk_score"] >= 61:
        return {"level": "ALERT-WORTHY INDICATOR",
                "explanation": "Meets alerting thresholds; needs triage before it can be called a threat."}
    return {"level": "INDICATOR", "explanation": "Validated indicator with context. No confirmed malicious activity."}


# ---------------------------------------------------------------------------
# Writes (create / update / notes)
# ---------------------------------------------------------------------------
def next_threat_id(conn) -> str:
    year = date.today().year
    rows = conn.execute("SELECT threat_id FROM threats WHERE threat_id LIKE ?", (f"THR-{year}-%",)).fetchall()
    nums = [int(r[0].rsplit("-", 1)[1]) for r in rows if r[0].rsplit("-", 1)[1].isdigit()]
    return f"THR-{year}-{(max(nums) + 1) if nums else 1:03d}"


def create_threat(conn, payload: dict, role: str, config: dict | None = None) -> dict:
    """POST /api/threats - normalise, validate, score, store, and alert."""
    from backend.services.alert_engine import generate_threat_alert, store_alerts
    from backend.services.correlation_engine import count_correlated

    rec = normalize_threat_input(payload)
    rec["threat_id"] = next_threat_id(conn)
    if conn.execute("SELECT 1 FROM threats WHERE threat_id=?", (rec["threat_id"],)).fetchone():
        raise ValueError(["Duplicate threat_id."])
    correlated = count_correlated(conn, rec["indicator_value"], rec["campaign_id"])
    score_record(rec, correlated, date.today(),
                 corroborating=int(payload.get("corroborating_sources", 0) or 0),
                 analyst_verified=bool(payload.get("analyst_verified", False)))
    sources = ensure_sources(conn)
    insert_threat(conn, rec, sources)
    alerts = generate_threat_alert(dict(rec), thresholds=config)
    store_alerts(conn, alerts)
    audit(conn, role, "CREATE_THREAT", rec["threat_id"], rec["threat_name"])
    conn.commit()
    return get_threat_detail(conn, rec["threat_id"])


UPDATABLE_FIELDS = ("status", "threat_name", "description", "observation_count", "last_seen")


def update_threat(conn, threat_id: str, payload: dict, role: str) -> dict | None:
    """PUT /api/threats/{id} - lifecycle update with timeline + audit + re-scoring."""
    current = get_threat(conn, threat_id)
    if not current:
        return None
    unknown = [k for k in payload if k not in UPDATABLE_FIELDS]
    if unknown:
        raise ValueError([f"Field(s) not updatable: {', '.join(unknown)}. Allowed: {', '.join(UPDATABLE_FIELDS)}"])
    tid = current["threat_id"]
    now = utc_now()
    today = date.today().isoformat()
    updates = {}
    if "status" in payload:
        status = str(payload["status"]).upper()
        if status not in THREAT_STATUSES:
            raise ValueError([f"status must be one of {', '.join(THREAT_STATUSES)}."])
        if status != current["status"]:
            updates["status"] = status
            add_timeline_event(conn, tid, today, status if status != "UNDER_REVIEW" else "INVESTIGATION_STARTED",
                               f"Status changed {current['status']} -> {status} by {role}.")
    if "threat_name" in payload:
        name = sanitize_text(payload["threat_name"], 200)
        if not name:
            raise ValueError(["threat_name cannot be empty."])
        updates["threat_name"] = name
    if "description" in payload:
        updates["description"] = sanitize_text(payload["description"], 2000)
    if "last_seen" in payload:
        errs = []
        ls = _norm_date(payload["last_seen"], "last_seen", errs)
        if errs:
            raise ValueError(errs)
        updates["last_seen"] = ls
    if "observation_count" in payload:
        try:
            obs = int(payload["observation_count"])
        except (TypeError, ValueError):
            raise ValueError(["observation_count must be an integer."])
        if obs < current["observation_count"]:
            raise ValueError(["observation_count can only increase (observations are append-only)."])
        if obs > current["observation_count"]:
            updates["observation_count"] = obs
            add_timeline_event(conn, tid, today, "NEW_OBSERVATIONS",
                               f"Observations increased {current['observation_count']} -> {obs}.")
    if not updates:
        return get_threat_detail(conn, tid)

    # Re-score when evidence changed.
    if {"observation_count", "last_seen"} & updates.keys():
        from backend.services.correlation_engine import count_correlated
        merged = dict(current, **updates)
        rec = {"source_name": current.get("source_name") or "Unknown Source",
               "impact_level": current.get("impact_level") or current["severity"],
               "confidence_score": current["confidence_score"], "last_seen": merged["last_seen"],
               "observation_count": merged["observation_count"], "behavior_observed": current["behavior_observed"],
               "cve_id": current.get("cve_id")}
        score_record(rec, count_correlated(conn, current["indicator_value"], current.get("campaign_id"), tid),
                     date.today())
        if rec["risk_score"] != current["risk_score"]:
            direction = "RISK_INCREASED" if rec["risk_score"] > current["risk_score"] else "RISK_DECREASED"
            add_timeline_event(conn, tid, today, direction,
                               f"Risk {current['risk_score']} -> {rec['risk_score']} ({rec['severity']}).")
        updates.update(risk_score=rec["risk_score"], severity=rec["severity"],
                       risk_breakdown_json=json.dumps(rec["risk_breakdown"]))
    updates["updated_at"] = now
    sets = ", ".join(f"{k} = ?" for k in updates)
    conn.execute(f"UPDATE threats SET {sets} WHERE threat_id = ?", list(updates.values()) + [tid])
    audit(conn, role, "UPDATE_THREAT", tid, json.dumps({k: v for k, v in updates.items()
                                                         if k != "risk_breakdown_json"}))
    conn.commit()
    return get_threat_detail(conn, tid)


def add_analyst_note(conn, threat_id: str, note: str, role: str, author: str = "analyst") -> dict | None:
    if not get_threat(conn, threat_id):
        return None
    clean = sanitize_text(note, 2000)
    if len(clean) < 3:
        raise ValueError(["note must contain at least 3 characters of text."])
    author = sanitize_text(author, 40) or "analyst"
    now = utc_now()
    cur = conn.execute("INSERT INTO analyst_notes(threat_id, author, note, created_at) VALUES (?,?,?,?)",
                       (threat_id.upper(), author, clean, now))
    add_timeline_event(conn, threat_id.upper(), now[:10], "ANALYST_NOTE", f"Note added by {author}.")
    audit(conn, role, "ADD_NOTE", threat_id.upper(), clean[:80])
    conn.commit()
    return {"note_id": cur.lastrowid, "threat_id": threat_id.upper(), "author": author, "note": clean,
            "created_at": now}


# ---------------------------------------------------------------------------
# Dashboard analytics
# ---------------------------------------------------------------------------
def _counts(conn, sql, params=()) -> dict:
    return {r[0]: r[1] for r in conn.execute(sql, params)}


def dashboard_stats(conn) -> dict:
    one = lambda sql, p=(): conn.execute(sql, p).fetchone()[0]  # noqa: E731
    active = ",".join(f"'{s}'" for s in ACTIVE_STATUSES)
    total = one("SELECT COUNT(*) FROM threats")
    stats = {
        "cards": {
            "total_threats": total,
            "critical_threats": one("SELECT COUNT(*) FROM threats WHERE severity='CRITICAL'"),
            "high_threats": one("SELECT COUNT(*) FROM threats WHERE severity='HIGH'"),
            "active_indicators": one(
                f"SELECT COUNT(DISTINCT i.normalized_value) FROM indicators i JOIN threats t "
                f"ON t.threat_id=i.threat_id WHERE t.status IN ({active})"),
            "open_investigations": one("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')"),
            "average_confidence": round(one("SELECT COALESCE(AVG(confidence_score),0) FROM threats"), 1),
            "vulnerabilities_tracked": one("SELECT COUNT(*) FROM vulnerabilities"),
        },
        "evidence_ladder": {
            "observations": one("SELECT COALESCE(SUM(observation_count),0) FROM threats"),
            "indicators": one("SELECT COUNT(DISTINCT normalized_value) FROM indicators"),
            "alerts": one("SELECT COUNT(*) FROM alerts"),
            "threats": one(f"SELECT COUNT(*) FROM threats WHERE status IN ('UNDER_REVIEW','MONITORING') "
                           f"AND risk_score >= 61"),
            "incidents": 0,
            "incident_note": "No incidents confirmed. An incident needs confirmed impact, declared by an analyst.",
        },
        "by_severity": _counts(conn, "SELECT severity, COUNT(*) FROM threats GROUP BY severity"),
        "by_category": _counts(conn, "SELECT category, COUNT(*) FROM threats GROUP BY category ORDER BY 2 DESC"),
        "by_indicator_type": _counts(conn, "SELECT indicator_type, COUNT(*) FROM indicators WHERE is_primary=1 "
                                           "GROUP BY indicator_type ORDER BY 2 DESC"),
        "by_status": _counts(conn, "SELECT status, COUNT(*) FROM threats GROUP BY status"),
        "risk_distribution": _histogram(conn, "risk_score"),
        "confidence_distribution": _histogram(conn, "confidence_score"),
        "vulnerabilities_by_severity": _counts(conn, "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"),
        "top_categories_by_risk": [dict(r) for r in conn.execute(
            f"SELECT category, COUNT(*) AS count, ROUND(AVG(risk_score),1) AS avg_risk FROM threats "
            f"WHERE status IN ({active}) GROUP BY category ORDER BY avg_risk DESC LIMIT 5")],
        "top_tactics": attack_stats(conn)["tactics"][:8],
        "category_labels": {k: v["label"] for k, v in THREAT_CATEGORIES.items()},
        "severity_order": list(SEVERITY_LEVELS),
        "status_order": list(THREAT_STATUSES),
    }
    return stats


def _histogram(conn, column: str) -> dict:
    bins = [f"{i}-{i + 9}" for i in range(0, 100, 10)]
    bins[-1] = "90-100"
    counts = [0] * 10
    for (value,) in conn.execute(f"SELECT {column} FROM threats"):
        counts[min(9, int(value) // 10)] += 1
    return {"labels": bins, "counts": counts}


def trend_stats(conn, weeks: int = 26) -> dict:
    """Weekly counts by first_seen (pandas resampling)."""
    import pandas as pd

    df = pd.read_sql_query("SELECT first_seen, severity FROM threats", conn)
    if df.empty:
        return {"labels": [], "total": [], "high_or_critical": []}
    df["first_seen"] = pd.to_datetime(df["first_seen"])
    df["hc"] = df["severity"].isin(["HIGH", "CRITICAL"]).astype(int)
    weekly = df.set_index("first_seen").resample("W-MON", label="left", closed="left").agg(
        total=("severity", "count"), high_or_critical=("hc", "sum")).tail(weeks)
    return {
        "labels": [d.strftime("%Y-%m-%d") for d in weekly.index],
        "total": weekly["total"].astype(int).tolist(),
        "high_or_critical": weekly["high_or_critical"].astype(int).tolist(),
        "note": "Weekly count of threat records by first-seen date (week starting Monday).",
    }


def attack_stats(conn) -> dict:
    from backend.services.attack_mapper import ATTACK_TACTICS_ORDER

    tactic_counts = _counts(conn, "SELECT tactic, COUNT(*) FROM attack_mappings GROUP BY tactic")
    tactics = sorted(({"tactic": t, "count": c} for t, c in tactic_counts.items()),
                     key=lambda x: -x["count"])
    techniques = [dict(r, reference_url=attack_technique_url(r["technique_id_optional"])) for r in conn.execute(
        "SELECT technique_id_optional, technique, tactic, COUNT(*) AS count FROM attack_mappings "
        "GROUP BY technique_id_optional, technique, tactic ORDER BY count DESC")]
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    mapped = conn.execute("SELECT COUNT(DISTINCT threat_id) FROM attack_mappings").fetchone()[0]
    matrix = {t: [x for x in techniques if x["tactic"] == t] for t in ATTACK_TACTICS_ORDER}
    return {"tactics": tactics, "techniques": techniques, "matrix": matrix,
            "tactic_order": ATTACK_TACTICS_ORDER, "mapped_records": mapped, "unmapped_records": total - mapped,
            "note": "Records are mapped only when a behaviour was observed. Feed-only indicators stay unmapped."}


def reliability_reference() -> dict:
    return {"levels": RELIABILITY_LEVELS,
            "sources": {name: get_source_reliability(name) for name in INTEL_SOURCES}}
