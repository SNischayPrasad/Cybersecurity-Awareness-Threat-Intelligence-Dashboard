"""
Risk, Confidence and Source-Reliability Engine
==============================================

Two different questions, two different scores:

* RISK SCORE (0-100)       -> "How concerning could this indicator/event be?"
* CONFIDENCE SCORE (0-100) -> "How much do we trust the intelligence behind it?"

A HIGH risk score does NOT mean a confirmed compromise. It means the item
deserves analyst attention sooner. Confirmation only happens through
investigation.

Risk weighting (sums to 100%)
-----------------------------
Severity / impact ........ 30%
Confidence ............... 25%
Recency .................. 15%
Observation frequency .... 10%
Source reliability ....... 10%
Context / correlation .... 10%
"""
from __future__ import annotations

import math
from datetime import date, datetime

SEVERITY_LEVELS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Points used as the "impact" input to risk scoring.
SEVERITY_POINTS = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 100}

RISK_WEIGHTS = {
    "severity": 0.30,
    "confidence": 0.25,
    "recency": 0.15,
    "frequency": 0.10,
    "source_reliability": 0.10,
    "context": 0.10,
}

# ---------------------------------------------------------------------------
# Source reliability (inspired by the "Admiralty" A-F source grading idea,
# simplified to four levels for this project).
# ---------------------------------------------------------------------------
RELIABILITY_LEVELS = {
    "A": {"label": "Highly Reliable", "points": 100, "confidence_base": 45},
    "B": {"label": "Usually Reliable", "points": 75, "confidence_base": 35},
    "C": {"label": "Fairly Reliable", "points": 50, "confidence_base": 25},
    "D": {"label": "Reliability Unknown", "points": 25, "confidence_base": 10},
}

INTEL_SOURCES = {
    "Internal SOC": {"reliability": "A", "type": "Internal telemetry",
                     "description": "Sightings confirmed by our own (synthetic) security monitoring."},
    "Security Vendor": {"reliability": "B", "type": "Commercial intelligence",
                        "description": "Curated vendor intelligence with a good historical track record."},
    "Research Report": {"reliability": "B", "type": "Published research",
                        "description": "Indicators extracted from a (fictional) published research write-up."},
    "Public Threat Feed": {"reliability": "C", "type": "Open-source feed",
                           "description": "Free community/public feed; useful but noisier."},
    "Community Submission": {"reliability": "C", "type": "Sharing community",
                             "description": "Submitted by peers in an information-sharing group."},
    "Unknown Source": {"reliability": "D", "type": "Unverified",
                       "description": "Provenance unknown - treat with caution until corroborated."},
}


def get_source_reliability(source_name: str) -> dict:
    """Return reliability grade + label for a named source (defaults to D)."""
    src = INTEL_SOURCES.get(source_name, INTEL_SOURCES["Unknown Source"])
    grade = src["reliability"]
    return {
        "source_name": source_name if source_name in INTEL_SOURCES else "Unknown Source",
        "reliability": grade,
        "reliability_label": RELIABILITY_LEVELS[grade]["label"],
        "points": RELIABILITY_LEVELS[grade]["points"],
        "source_type": src["type"],
        "description": src["description"],
    }


# ---------------------------------------------------------------------------
# Helper scoring functions
# ---------------------------------------------------------------------------
def _to_date(value) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "")).date()


def days_since(value, reference_date=None) -> int:
    d = _to_date(value)
    ref = _to_date(reference_date) or date.today()
    if d is None:
        return 9999
    return max(0, (ref - d).days)


def recency_score(days: int) -> int:
    """Fresh intelligence matters more; stale indicators decay."""
    if days <= 7:
        return 100
    if days <= 30:
        return 75
    if days <= 90:
        return 50
    if days <= 180:
        return 25
    return 10


def frequency_score(observation_count: int) -> int:
    """Log scale so 1000 sightings is not 1000x worse than 1 sighting.
    1 -> 20, 3 -> 40, 7 -> 60, 15 -> 80, 31+ -> 100."""
    n = max(0, int(observation_count or 0))
    return min(100, round(20 * math.log2(n + 1)))


def context_score(related_alerts=0, correlated_indicators=0, has_attack_mapping=False, has_cve=False) -> int:
    """Context/correlation: related evidence makes an item more meaningful."""
    score = related_alerts * 20 + correlated_indicators * 10
    score += 20 if has_attack_mapping else 0
    score += 10 if has_cve else 0
    return min(100, score)


def classify_risk(score: float) -> str:
    """Map a 0-100 score to a severity band."""
    s = round(score)
    if s <= 20:
        return "INFORMATIONAL"
    if s <= 40:
        return "LOW"
    if s <= 60:
        return "MEDIUM"
    if s <= 80:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Main scoring functions
# ---------------------------------------------------------------------------
def calculate_threat_risk(
    severity: str,
    confidence: float,
    last_seen=None,
    observation_count: int = 1,
    source_reliability: str = "D",
    related_alerts: int = 0,
    correlated_indicators: int = 0,
    has_attack_mapping: bool = False,
    has_cve: bool = False,
    reference_date=None,
) -> dict:
    """Weighted 0-100 risk score with an explanation of every component.

    `severity` here is the *impact* of the threat type if it were real
    (analyst/feed supplied). The OUTPUT classification is derived from the
    final score so the displayed severity always matches the risk band.
    """
    severity = (severity or "MEDIUM").upper()
    if severity not in SEVERITY_POINTS:
        raise ValueError(f"Unknown severity '{severity}'")
    confidence = max(0.0, min(100.0, float(confidence)))
    grade = (source_reliability or "D").upper()
    if grade not in RELIABILITY_LEVELS:
        grade = "D"

    age = days_since(last_seen, reference_date) if last_seen else 0
    components = {
        "severity": SEVERITY_POINTS[severity],
        "confidence": confidence,
        "recency": recency_score(age),
        "frequency": frequency_score(observation_count),
        "source_reliability": RELIABILITY_LEVELS[grade]["points"],
        "context": context_score(related_alerts, correlated_indicators, has_attack_mapping, has_cve),
    }
    weighted = {k: round(v * RISK_WEIGHTS[k], 2) for k, v in components.items()}
    score = int(round(sum(weighted.values())))
    score = max(0, min(100, score))
    return {
        "risk_score": score,
        "classification": classify_risk(score),
        "components": components,
        "weighted_components": weighted,
        "days_since_last_seen": age,
        "note": "High risk means 'prioritise for review' - it is NOT proof of compromise.",
    }


def calculate_confidence(
    source_reliability: str = "D",
    corroborating_sources: int = 0,
    validated: bool = True,
    has_context: bool = False,
    analyst_verified: bool = False,
    days_since_last_seen: int = 0,
) -> int:
    """0-100 confidence in the intelligence item itself.

    Base from source grade + corroboration + validation + context + analyst review,
    minus a staleness penalty.
    """
    grade = (source_reliability or "D").upper()
    base = RELIABILITY_LEVELS.get(grade, RELIABILITY_LEVELS["D"])["confidence_base"]
    score = base
    score += min(30, max(0, int(corroborating_sources)) * 10)  # independent sources agree
    score += 5 if validated else 0
    score += 10 if has_context else 0
    score += 5 if analyst_verified else 0
    if days_since_last_seen > 180:
        score -= 20
    elif days_since_last_seen > 90:
        score -= 10
    elif days_since_last_seen > 30:
        score -= 5
    if not validated:
        score = min(score, 20)  # malformed data can never be high-confidence
    return max(0, min(100, int(score)))


def interpret_risk_confidence(risk: int, confidence: int) -> str:
    """Plain-English reading of the risk/confidence pair for analysts."""
    high_risk = risk >= 61
    high_conf = confidence >= 60
    if high_risk and high_conf:
        return "High-confidence intelligence with meaningful risk - prioritise triage."
    if high_risk and not high_conf:
        return "Potentially serious, but evidence quality is weak - validate before acting."
    if not high_risk and high_conf:
        return "Well-supported intelligence with limited risk - monitor or document."
    return "Low risk and limited evidence - low priority, keep for context."
