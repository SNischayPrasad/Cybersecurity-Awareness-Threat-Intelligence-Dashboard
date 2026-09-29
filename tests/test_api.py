"""Tests 12, 16-17, 22-23, 26-31, 33-35, 37-38: REST API, database and security behaviour."""
import socket

from backend.database import get_connection
from backend.services.enrichment_engine import enrich_indicator
from tests.conftest import ADMIN, ANALYST, DEMO_ID

NEW_THREAT = {
    "threat_name": "Synthetic Test Phishing Domain",
    "threat_category": "PHISHING",
    "indicator_type": "DOMAIN",
    "indicator_value": "test-lure.invalid",
    "severity": "HIGH",
    "source_name": "Internal SOC",
    "behavior_observed": "email_link_lure",
    "corroborating_sources": 2,
    "description": "Created by automated test. <script>alert(1)</script>",
}


def test_12_threat_creation(client):
    r = client.post("/api/threats", json=NEW_THREAT, headers=ADMIN)
    assert r.status_code == 201, r.get_json()
    t = r.get_json()
    assert t["threat_id"].startswith("THR-") and t["indicator_value"] == "test-lure.invalid"
    assert 0 <= t["risk_score"] <= 100 and 0 <= t["confidence_score"] <= 100
    assert t["attack_mappings"][0]["technique_id_optional"] == "T1566.002"
    assert "<script>" not in t["description"]  # sanitised on the way in


def test_16_ioc_enrichment(db):
    r = enrich_indicator(db, "198.51.100.25")
    assert r["known_in_dataset"] and r["indicator_type"] == "IP"
    assert r["risk_score"] == 78 and r["confidence_score"] == 85 and r["status"] == "MONITORING"
    assert "Phishing" in r["associated_category_labels"]
    related = {x["indicator_value"] for x in r["related_indicators"]}
    assert "login-check.invalid" in related
    assert r["attack_mappings"] and r["analyst_notes"]
    unknown = enrich_indicator(db, "203.0.113.250")
    assert unknown["known_in_dataset"] is False and "NOT evidence" in unknown["message"]


def test_17_indicator_search_never_touches_network(client, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("Network access attempted!")
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    for q in ("login-check.invalid", "hxxps://login-check[.]invalid/verify/session", "198.51.100.25"):
        r = client.get("/api/indicators/search", query_string={"q": q})
        assert r.status_code == 200
        assert r.get_json()["network_activity"].startswith("NONE")
    assert client.get("/api/indicators/search").status_code == 400


def test_22_alert_status_update_requires_analyst(client, db):
    alert_id = db.execute("SELECT alert_id FROM alerts LIMIT 1").fetchone()[0]
    url = f"/api/alerts/{alert_id}/status"
    assert client.put(url, json={"status": "INVESTIGATING"}).status_code == 401
    assert client.put(url, json={"status": "INVESTIGATING"}, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.put(url, json={"status": "MAYBE"}, headers=ANALYST).status_code == 422
    r = client.put(url, json={"status": "FALSE_POSITIVE", "comment": "benign test"}, headers=ANALYST)
    assert r.status_code == 200 and r.get_json()["status"] == "FALSE_POSITIVE"
    audit = db.execute("SELECT actor_role, action FROM audit_log WHERE target=?", (alert_id,)).fetchone()
    assert tuple(audit) == ("analyst", "UPDATE_ALERT_STATUS")
    assert client.put("/api/alerts/ALR-99999/status", json={"status": "NEW"}, headers=ANALYST).status_code == 404


def test_23_analyst_notes(client):
    r = client.post(f"/api/threats/{DEMO_ID}/notes", json={"note": "Checked proxy logs <b>no hits</b>"}, headers=ANALYST)
    assert r.status_code == 201 and r.get_json()["note"] == "Checked proxy logs no hits"
    detail = client.get(f"/api/threats/{DEMO_ID}").get_json()
    assert any(n["note"] == "Checked proxy logs no hits" for n in detail["analyst_notes"])
    assert any(e["event_type"] == "ANALYST_NOTE" for e in detail["timeline"])
    assert client.post(f"/api/threats/{DEMO_ID}/notes", json={"note": "  "}, headers=ANALYST).status_code == 422
    assert client.post(f"/api/threats/{DEMO_ID}/notes", json={"note": "no key"}).status_code == 401


def test_26_dashboard_statistics(client, db):
    s = client.get("/api/dashboard/stats").get_json()
    total = db.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    assert s["cards"]["total_threats"] == total == 204
    assert sum(s["by_severity"].values()) == total
    assert sum(s["risk_distribution"]["counts"]) == total
    assert s["evidence_ladder"]["incidents"] == 0
    t = client.get("/api/dashboard/trends").get_json()
    assert len(t["labels"]) == len(t["total"]) > 0


def test_27_severity_filtering(client):
    data = client.get("/api/threats?severity=HIGH,CRITICAL&page_size=100").get_json()
    assert data["total"] > 0
    assert all(t["severity"] in ("HIGH", "CRITICAL") for t in data["items"])


def test_28_category_filtering(client):
    data = client.get("/api/threats?category=PHISHING&page_size=100").get_json()
    assert data["total"] > 0 and all(t["category"] == "PHISHING" for t in data["items"])


def test_29_threat_sorting(client):
    for sort, key in (("risk", "risk_score"), ("confidence", "confidence_score"), ("observed", "observation_count")):
        items = client.get(f"/api/threats?sort={sort}&page_size=50").get_json()["items"]
        values = [t[key] for t in items]
        assert values == sorted(values, reverse=True), sort
    newest = [t["last_seen"] for t in client.get("/api/threats?sort=newest&page_size=50").get_json()["items"]]
    assert newest == sorted(newest, reverse=True)


def test_30_awareness_module_retrieval(client):
    data = client.get("/api/awareness/modules").get_json()
    assert data["count"] == 15
    m = client.get("/api/awareness/modules/phishing").get_json()
    for field in ("what_is_it", "why_it_matters", "warning_signs", "safe_practices", "what_to_do"):
        assert m[field]
    assert client.get("/api/awareness/modules/nope").status_code == 404


def test_31_quiz_scoring(client, app):
    import json
    from pathlib import Path
    quiz = client.get("/api/quiz").get_json()
    assert quiz["count"] >= 30 and "answer" not in quiz["questions"][0]  # answers never sent to browser
    key = json.loads((Path(app.config["AWARENESS_DIR"]) / "quiz_questions.json").read_text(encoding="utf-8"))
    r = client.post("/api/quiz/submit", json={"answers": {q["id"]: q["answer"] for q in key}})
    body = r.get_json()
    assert r.status_code == 201 and body["overall_score"] == 100 and body["band"] == "Strong Awareness"
    assert all(v == 100 for v in body["category_scores"].values()) and body["weakest_areas"] == []
    wrong = {q["id"]: ("A" if q["answer"] != "A" else "B") for q in key}
    low = client.post("/api/quiz/submit", json={"answers": wrong}).get_json()
    assert low["overall_score"] == 0 and low["band"] == "Needs Improvement"
    assert all(rec["action"] == "Complete" for rec in low["recommendations"])


def test_33_empty_dataset(empty_app):
    c = empty_app.test_client()
    s = c.get("/api/dashboard/stats").get_json()
    assert s["cards"]["total_threats"] == 0 and s["cards"]["average_confidence"] == 0
    assert c.get("/api/threats").get_json()["items"] == []
    assert c.get("/api/dashboard/trends").get_json()["labels"] == []
    assert c.get("/api/executive/summary").status_code == 200
    assert c.get("/api/indicators/search?q=198.51.100.25").get_json()["known_in_dataset"] is False


def test_34_api_validation(client):
    bad = dict(NEW_THREAT, indicator_value="not a domain!")
    r = client.post("/api/threats", json=bad, headers=ADMIN)
    assert r.status_code == 422 and r.get_json()["details"]
    assert client.post("/api/threats", data="nope", headers=ADMIN).status_code == 400
    assert client.post("/api/threats", json=dict(NEW_THREAT, threat_category="ALIENS"), headers=ADMIN).status_code == 422
    assert client.get("/api/threats?page=abc").status_code == 400
    assert client.get("/api/threats/THR-0000-999").status_code == 404
    assert client.put(f"/api/threats/{DEMO_ID}", json={"risk_score": 1}, headers=ADMIN).status_code == 422
    assert client.post("/api/vulnerabilities/prioritize", json={"cvss_score": 42}).status_code == 422
    assert client.get("/api/does-not-exist").status_code == 404


def test_35_database_persistence(app, client):
    created = client.post("/api/threats", json=NEW_THREAT, headers=ADMIN).get_json()
    tid = created["threat_id"]
    r = client.put(f"/api/threats/{tid}", json={"status": "UNDER_REVIEW", "observation_count": 40}, headers=ANALYST)
    assert r.status_code == 200
    # A brand-new connection (like a server restart) sees the same data.
    conn = get_connection(app.config["DATABASE_PATH"])
    try:
        row = conn.execute("SELECT status, observation_count FROM threats WHERE threat_id=?", (tid,)).fetchone()
        assert tuple(row) == ("UNDER_REVIEW", 40)
        events = [e[0] for e in conn.execute("SELECT event_type FROM threat_timeline WHERE threat_id=?", (tid,))]
        assert "NEW_OBSERVATIONS" in events and "INVESTIGATION_STARTED" in events
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE target=?", (tid,)).fetchone()[0] >= 2
    finally:
        conn.close()


def test_37_rbac_analyst_cannot_create_threats(client):
    r = client.post("/api/threats", json=NEW_THREAT, headers=ANALYST)
    assert r.status_code == 403
    assert client.put(f"/api/threats/{DEMO_ID}", json={"threat_name": "x"}, headers=ANALYST).status_code == 403
    assert client.get("/api/auth/whoami", headers=ADMIN).get_json()["role"] == "admin"


def test_38_security_headers_and_demo_scenario(client):
    r = client.get(f"/api/threats/{DEMO_ID}")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    t = r.get_json()
    assert t["threat_name"] == "Synthetic Credential Phishing Campaign"
    assert (t["risk_score"], t["confidence_score"], t["severity"], t["status"]) == (78, 85, "HIGH", "MONITORING")
    assert "198.51.100.25" in {i["indicator_value"] for i in t["indicators"]}
    assert t["evidence_level"]["level"] == "THREAT"  # not "INCIDENT"
