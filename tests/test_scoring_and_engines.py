"""Tests 13-15, 18-21, 24-25, 32, 36, 40: scoring, correlation, alerts, ATT&CK, vulnerabilities, safety."""
import ipaddress
from datetime import date

import pytest

from backend.services.alert_engine import correlate_alerts, generate_threat_alert, simulate_observation_burst
from backend.services.attack_mapper import map_to_attack
from backend.services.awareness_service import generate_learning_recommendations
from backend.services.correlation_engine import correlate_threats
from backend.services.ioc_validator import is_documentation_ip, is_reserved_domain, validate_indicator
from backend.services.risk_engine import (
    calculate_confidence,
    calculate_threat_risk,
    classify_risk,
    get_source_reliability,
    interpret_risk_confidence,
)
from backend.services.vulnerability_service import calculate_vulnerability_priority
from backend.utils.security import sanitize_text
from data.generate_threat_data import generate_threat_records

REF = date(2026, 9, 29)


def test_13_risk_calculation():
    r = calculate_threat_risk("HIGH", 85, "2026-09-27", 5, "B", correlated_indicators=3,
                              has_attack_mapping=True, reference_date=REF)
    assert r["risk_score"] == 78 and r["classification"] == "HIGH"
    assert set(r["components"]) == {"severity", "confidence", "recency", "frequency", "source_reliability", "context"}
    # Stale, low-confidence, single sighting from an unknown source scores much lower.
    low = calculate_threat_risk("HIGH", 20, "2025-01-01", 1, "D", reference_date=REF)
    assert low["risk_score"] < r["risk_score"]
    assert classify_risk(20) == "INFORMATIONAL" and classify_risk(81) == "CRITICAL"
    with pytest.raises(ValueError):
        calculate_threat_risk("SEVERE", 50)


def test_14_confidence_calculation_and_interpretation():
    assert calculate_confidence("B", corroborating_sources=3, validated=True, has_context=True,
                                analyst_verified=True, days_since_last_seen=2) == 85
    assert calculate_confidence("A", 5, validated=False) <= 20  # malformed data is never high-confidence
    assert calculate_confidence("C", days_since_last_seen=200) < calculate_confidence("C", days_since_last_seen=1)
    assert "evidence quality is weak" in interpret_risk_confidence(90, 25)
    assert "High-confidence" in interpret_risk_confidence(70, 95)


def test_15_source_reliability():
    assert get_source_reliability("Internal SOC")["reliability"] == "A"
    assert get_source_reliability("Security Vendor")["reliability_label"] == "Usually Reliable"
    unknown = get_source_reliability("Random Blog")
    assert unknown["reliability"] == "D" and unknown["source_name"] == "Unknown Source"


def _rec(tid, ind, campaign=None, first="2026-09-01", last="2026-09-05", itype="DOMAIN", cat="PHISHING", risk=70):
    return {"threat_id": tid, "indicator_value": ind, "indicator_type": itype, "category": cat,
            "campaign_id": campaign, "first_seen": first, "last_seen": last, "risk_score": risk,
            "confidence_score": 80}


def test_18_threat_correlation():
    records = [
        _rec("T1", "login-check.invalid", "CMP-1"),
        _rec("T2", "198.51.100.25", "CMP-1", itype="IP"),
        _rec("T3", "a" * 64, "CMP-1", itype="FILE_HASH", cat="MALWARE"),
        _rec("T4", "unrelated.example.org"),
    ]
    clusters = correlate_threats(records)
    assert len(clusters) == 1
    c = clusters[0]
    assert c["threat_ids"] == ["T1", "T2", "T3"]
    assert set(c["indicator_types"]) == {"DOMAIN", "IP", "FILE_HASH"}
    assert "shared campaign_id" in c["link_reasons"]
    assert "not proof of attribution" in c["note"]
    # Same campaign but far-apart observation windows -> NOT linked.
    far = [_rec("A", "x.invalid", "CMP-2", "2026-01-01", "2026-01-02"), _rec("B", "y.invalid", "CMP-2", "2026-09-01", "2026-09-02")]
    assert correlate_threats(far, window_days=30) == []


def test_19_duplicate_observation_links_records():
    records = [_rec("F1", "203.0.113.9", itype="IP"), _rec("F2", "203.0.113.9", itype="IP")]
    clusters = correlate_threats(records)
    assert clusters and clusters[0]["link_reasons"] == ["shared indicator value"]


def test_20_alert_generation():
    base = {"threat_id": "T1", "indicator_value": "198.51.100.25", "status": "NEW", "last_seen": "2026-09-27",
            "observation_count": 3, "severity": "HIGH"}
    high = generate_threat_alert(dict(base, risk_score=75, confidence_score=85))
    assert [a["alert_type"] for a in high] == ["HIGH_RISK_INDICATOR"]
    assert generate_threat_alert(dict(base, risk_score=40, confidence_score=90)) == []
    weak = generate_threat_alert(dict(base, risk_score=75, confidence_score=25))
    assert weak[0]["alert_type"] == "UNVERIFIED_HIGH_RISK" and weak[0]["severity"] == "MEDIUM"
    repeated = generate_threat_alert(dict(base, risk_score=30, confidence_score=30, observation_count=80))
    assert repeated[0]["alert_type"] == "REPEATED_OBSERVATION" and repeated[0]["observation_count"] == 80


def test_21_alert_correlation_prevents_alert_fatigue():
    threat = {"threat_id": "T9", "indicator_value": "203.0.113.77", "status": "NEW", "risk_score": 60,
              "confidence_score": 60, "timestamp": "2026-09-29T10:00:00"}
    burst = simulate_observation_burst(threat, count=100, minutes=5)
    merged = correlate_alerts(burst, window_minutes=5)
    assert len(burst) == 100 and len(merged) == 1
    assert merged[0]["observation_count"] == 100
    # Two sightings 2 hours apart are separate alerts.
    a = dict(burst[0])
    b = dict(burst[0], timestamp="2026-09-29T12:30:00")
    assert len(correlate_alerts([a, b], window_minutes=60)) == 2


def test_24_attack_mapping_only_when_justified():
    m = map_to_attack("email_link_lure")
    assert m["technique_id_optional"] == "T1566.002" and m["tactic"] == "Initial Access"
    assert map_to_attack("files_encrypted")["technique_id_optional"] == "T1486"
    assert map_to_attack("reputation_only") is None  # insufficient context -> no guess
    assert map_to_attack("") is None


def test_25_vulnerability_prioritisation_uses_context():
    isolated = calculate_vulnerability_priority(9.8, "LOW", "ISOLATED", "NO_KNOWN_EXPLOITATION")
    exposed = calculate_vulnerability_priority(8.1, "CRITICAL", "INTERNET_FACING", "EXPLOITATION_REPORTED_DEMO", True)
    assert exposed["priority_score"] > isolated["priority_score"]
    assert exposed["priority_band"] == "P1" and isolated["priority_band"] in ("P3", "P4")
    with pytest.raises(ValueError):
        calculate_vulnerability_priority(11, "LOW", "ISOLATED", "NO_KNOWN_EXPLOITATION")
    with pytest.raises(ValueError):
        calculate_vulnerability_priority(5, "HUGE", "ISOLATED", "NO_KNOWN_EXPLOITATION")


def test_32_learning_recommendations():
    recs = {r["category"]: r for r in generate_learning_recommendations(
        {"Phishing": 40, "Passwords": 90, "Social Engineering": 55})}
    assert recs["Phishing"]["action"] == "Complete" and recs["Phishing"]["module_id"] == "phishing"
    assert recs["Social Engineering"]["action"] == "Review"
    assert recs["Passwords"]["recommendation"] == "No immediate module required."


def test_36_sanitize_text_strips_html_and_controls():
    dirty = '<script>alert("x")</script>Hello\x00 <b>analyst</b>'
    assert sanitize_text(dirty) == 'alert("x")Hello analyst'
    assert len(sanitize_text("a" * 5000, 100)) == 100


def test_40_generator_only_produces_safe_synthetic_indicators():
    records = generate_threat_records(300, seed=3, reference_date=REF)
    assert len(records) == 304  # 300 generated + 4 fixed demo-scenario records
    for r in records:
        assert r["data_label"] == "SYNTHETIC / DEMO ONLY"
        v, t = r["indicator_value"], r["indicator_type"]
        assert validate_indicator(v, t)["valid"], v
        if t == "IP":
            assert is_documentation_ip(ipaddress.ip_address(v)), v
        elif t == "DOMAIN":
            assert is_reserved_domain(v), v
        elif t in ("URL", "EMAIL"):
            host = v.split("//")[-1].split("/")[0] if t == "URL" else v.split("@")[1]
            assert is_reserved_domain(host), v
        elif t == "CVE":
            assert v.startswith("CVE-2099-")
