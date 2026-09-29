"""
Synthetic Threat Intelligence Dataset Generator
===============================================

Generates SAFE, FICTIONAL threat-intelligence records for the dashboard.

  * IP addresses come ONLY from documentation ranges:
      192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32
  * Domains use ONLY reserved names: example.com / example.org / example.net / *.invalid
  * URLs are built on those reserved domains - none of them resolve to real sites.
  * File hashes are RANDOM 64-hex strings - they do not match any real file.
  * CVE IDs use the fake year 2099 (CVE-2099-xxxx) so they never collide with real CVEs.

Every record is labelled "SYNTHETIC / DEMO ONLY".

Usage (from the project root):
    python data/generate_threat_data.py
    python data/generate_threat_data.py --count 5000 --seed 7
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.attack_mapper import map_to_attack  # noqa: E402
from backend.services.risk_engine import (  # noqa: E402
    INTEL_SOURCES,
    calculate_confidence,
    calculate_threat_risk,
    days_since,
)
from backend.services.vulnerability_service import (  # noqa: E402
    calculate_vulnerability_priority,
    cvss_severity,
)

DATA_LABEL = "SYNTHETIC / DEMO ONLY"

THREAT_FIELDS = [
    "threat_id", "timestamp", "threat_name", "threat_category", "indicator_type", "indicator_value",
    "source_name", "source_reliability", "confidence_score", "severity", "impact_level", "risk_score",
    "status", "first_seen", "last_seen", "observation_count", "campaign_id",
    "country_or_region_optional", "description", "behavior_observed",
    "mitre_tactic_optional", "mitre_technique_optional", "mitre_technique_id_optional",
    "cve_id_optional", "data_label",
]

VULN_FIELDS = [
    "cve_id", "product_category", "severity", "cvss_score", "published_date", "patch_available",
    "exploitation_status_demo", "asset_criticality", "exposure", "handles_sensitive_data",
    "priority_score", "priority_band", "description", "data_label",
]

# ---------------------------------------------------------------------------
# Category profiles: which indicator types / behaviours / impacts are typical.
# Numbers are relative weights.
# ---------------------------------------------------------------------------
CATEGORY_PROFILES = {
    "PHISHING": {
        "weight": 18,
        "types": {"DOMAIN": 4, "URL": 3, "EMAIL": 2, "IP": 1},
        "behaviors": {"email_link_lure": 4, "email_attachment_lure": 2, "credential_harvest_page": 3,
                      "voice_callback_lure": 1, "reputation_only": 3},
        "impact": {"LOW": 1, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 1},
        "names": ["Invoice-Lure Phishing", "Payroll Update Phishing", "Shared-Document Phishing",
                  "Parcel Delivery Phishing", "Password Expiry Phishing", "Tax Refund Phishing"],
    },
    "MALWARE": {
        "weight": 14,
        "types": {"FILE_HASH": 5, "DOMAIN": 2, "IP": 2, "URL": 1},
        "behaviors": {"user_opened_file": 3, "web_c2_beaconing": 3, "tool_download": 2,
                      "autostart_persistence": 2, "reputation_only": 3},
        "impact": {"MEDIUM": 3, "HIGH": 4, "CRITICAL": 2},
        "names": ["Loader Activity", "Info-Stealer Activity", "Remote Access Tool Activity",
                  "Malicious Macro Document", "Fake Installer Bundle"],
    },
    "RANSOMWARE": {
        "weight": 7,
        "types": {"FILE_HASH": 4, "DOMAIN": 2, "IP": 2},
        "behaviors": {"files_encrypted": 2, "backup_deletion": 2, "web_c2_beaconing": 2, "reputation_only": 2},
        "impact": {"HIGH": 3, "CRITICAL": 4},
        "names": ["Ransomware Precursor Activity", "Ransomware Encryptor Sample",
                  "Double-Extortion Infrastructure"],
    },
    "CREDENTIAL_THREATS": {
        "weight": 12,
        "types": {"IP": 5, "DOMAIN": 2, "URL": 2},
        "behaviors": {"password_spraying": 3, "brute_force": 3, "credential_harvest_page": 2,
                      "session_cookie_theft": 1, "reputation_only": 2},
        "impact": {"LOW": 1, "MEDIUM": 4, "HIGH": 3},
        "names": ["Password Spraying Source", "Credential Stuffing Burst", "Fake SSO Portal",
                  "Brute-Force Login Source"],
    },
    "WEB_THREATS": {
        "weight": 10,
        "types": {"URL": 4, "DOMAIN": 3, "IP": 2},
        "behaviors": {"drive_by_site": 2, "public_app_exploit_attempt": 3, "reputation_only": 3},
        "impact": {"LOW": 2, "MEDIUM": 4, "HIGH": 2},
        "names": ["Malicious Redirect Chain", "Web Exploit Scanner", "Compromised Site Injection",
                  "Look-alike Download Site"],
    },
    "NETWORK_THREATS": {
        "weight": 10,
        "types": {"IP": 1},
        "behaviors": {"external_scanning": 4, "ddos_traffic": 1, "remote_service_access": 2, "reputation_only": 3},
        "impact": {"INFORMATIONAL": 2, "LOW": 4, "MEDIUM": 3, "HIGH": 1},
        "names": ["Port Scanning Source", "VPN Login Probe Source", "Traffic Flood Source",
                  "Remote Desktop Probe Source"],
    },
    "VULNERABILITY_EXPOSURE": {
        "weight": 8,
        "types": {"CVE": 4, "IP": 1},
        "behaviors": {"public_app_exploit_attempt": 2, "reputation_only": 3},
        "impact": {"MEDIUM": 3, "HIGH": 3, "CRITICAL": 2},
        "names": ["Exposed Service Vulnerability", "Unpatched Gateway Advisory",
                  "Web Framework Vulnerability Advisory"],
    },
    "SOCIAL_ENGINEERING": {
        "weight": 8,
        "types": {"EMAIL": 3, "DOMAIN": 2},
        "behaviors": {"impersonation_pretext": 4, "voice_callback_lure": 2, "reputation_only": 2},
        "impact": {"LOW": 1, "MEDIUM": 3, "HIGH": 3},
        "names": ["Executive Impersonation", "Supplier Bank-Change Request", "Fake IT Helpdesk Call",
                  "Gift-Card Request Scam"],
    },
    "DATA_EXPOSURE": {
        "weight": 6,
        "types": {"URL": 3, "DOMAIN": 2, "IP": 2},
        "behaviors": {"cloud_storage_exposure": 3, "exfil_web_service": 2, "exfil_c2": 1, "reputation_only": 2},
        "impact": {"MEDIUM": 3, "HIGH": 3, "CRITICAL": 1},
        "names": ["Public Storage Bucket Exposure", "Unsanctioned Upload Destination",
                  "Paste-Site Data Mention"],
    },
    "ACCOUNT_SECURITY": {
        "weight": 7,
        "types": {"IP": 3, "EMAIL": 1},
        "behaviors": {"mfa_fatigue": 3, "valid_account_login_anomaly": 3, "session_cookie_theft": 2,
                      "reputation_only": 1},
        "impact": {"MEDIUM": 3, "HIGH": 3, "CRITICAL": 1},
        "names": ["MFA Fatigue Attempt", "Impossible-Travel Login Source", "Session Token Replay",
                  "Dormant Account Login"],
    },
}

SOURCE_WEIGHTS = {"Internal SOC": 2, "Security Vendor": 3, "Public Threat Feed": 3,
                  "Research Report": 1, "Community Submission": 1.5, "Unknown Source": 1}
REGIONS = ["North America", "Europe", "Asia-Pacific", "Latin America", "Middle East & Africa"]
CODENAME_A = ["Amber", "Cobalt", "Crimson", "Silent", "Velvet", "Iron", "Quiet", "Hollow", "Paper",
              "Glass", "Copper", "Frost", "Ember", "Lunar", "Shadow", "Granite"]
CODENAME_B = ["Heron", "Lynx", "Falcon", "Otter", "Viper", "Kestrel", "Badger", "Moth", "Raven",
              "Marten", "Gecko", "Wren", "Jackal", "Ibis", "Pike", "Newt"]
WORDS = ["secure", "login", "verify", "account", "update", "billing", "portal", "support", "docs",
         "share", "cloud", "mail", "helpdesk", "payroll", "invoice", "delivery", "auth", "sso",
         "files", "status", "notice", "wallet", "reset", "check", "office", "sync", "track", "pay"]
SAFE_BASE_DOMAINS = ["example.com", "example.org", "example.net"]


def wchoice(rng: random.Random, weights: dict):
    """Weighted random choice from {option: weight}."""
    return rng.choices(list(weights), weights=list(weights.values()), k=1)[0]


class IndicatorFactory:
    """Creates unique, SAFE indicator values."""

    def __init__(self, rng: random.Random, cve_ids: list[str], reserved: set[str]):
        self.rng = rng
        self.cve_ids = cve_ids
        self.used = set(reserved)

    def _unique(self, maker):
        for _ in range(50):
            value = maker()
            if value not in self.used:
                self.used.add(value)
                return value
        return value  # extremely rare: accept a duplicate (IP space is small)

    def ip(self):
        def make():
            if self.rng.random() < 0.08:
                return f"2001:db8:{self.rng.randint(1, 0xffff):x}::{self.rng.randint(1, 0xffff):x}"
            net = self.rng.choice(["192.0.2", "198.51.100", "203.0.113"])
            return f"{net}.{self.rng.randint(1, 254)}"
        return self._unique(make)

    def domain(self):
        def make():
            a, b = self.rng.sample(WORDS, 2)
            if self.rng.random() < 0.5:
                return f"{a}-{b}.invalid"
            return f"{a}-{b}.{self.rng.choice(SAFE_BASE_DOMAINS)}"
        return self._unique(make)

    def url(self):
        paths = ["login", "verify/session", "docs/view", "update/check", "download/report",
                 "account/reset", "invoice/{n}", "track/{n}"]

        def make():
            path = self.rng.choice(paths).replace("{n}", str(self.rng.randint(1000, 9999)))
            return f"https://{self.domain()}/{path}"
        return self._unique(make)

    def email(self):
        locals_ = ["billing", "it-support", "hr-notice", "no-reply", "ceo-office", "payroll",
                   "security-alert", "accounts", "helpdesk"]
        return self._unique(lambda: f"{self.rng.choice(locals_)}@{self.domain()}")

    def file_hash(self):
        # Random 256-bit value -> SHA-256-FORMAT string. It is NOT the hash of any real file.
        return self._unique(lambda: f"{self.rng.getrandbits(256):064x}")

    def cve(self):
        return self.rng.choice(self.cve_ids)

    def make(self, indicator_type: str) -> str:
        return {"IP": self.ip, "DOMAIN": self.domain, "URL": self.url, "EMAIL": self.email,
                "FILE_HASH": self.file_hash, "CVE": self.cve}[indicator_type]()


def describe(category: str, behavior: str, indicator_type: str, name: str) -> str:
    behavior_text = {
        "reputation_only": "listed on an intelligence feed without behavioural context",
        "email_link_lure": "seen in email lures containing links",
        "email_attachment_lure": "seen in email lures with attachments",
        "voice_callback_lure": "seen in messages urging a call to a fake support line",
        "credential_harvest_page": "associated with a fake sign-in page",
        "user_opened_file": "linked to a file a user opened",
        "web_c2_beaconing": "contacted periodically by an internal host (possible beaconing)",
        "tool_download": "used to download an additional tool",
        "autostart_persistence": "linked to a new autostart entry",
        "files_encrypted": "linked to mass file-encryption behaviour",
        "backup_deletion": "linked to backup-deletion attempts",
        "password_spraying": "the source of password-spraying attempts",
        "brute_force": "the source of repeated failed logins",
        "session_cookie_theft": "linked to session-token reuse",
        "public_app_exploit_attempt": "linked to exploit-like requests against a public app",
        "drive_by_site": "part of a malicious redirect chain",
        "external_scanning": "the source of systematic port scanning",
        "remote_service_access": "the source of remote-access login attempts",
        "ddos_traffic": "a source of flooding traffic",
        "cloud_storage_exposure": "an exposed cloud storage location",
        "exfil_web_service": "an unsanctioned upload destination",
        "exfil_c2": "receiving unusual outbound data volume",
        "impersonation_pretext": "used to impersonate a trusted person",
        "mfa_fatigue": "linked to repeated unexpected MFA prompts",
        "valid_account_login_anomaly": "the origin of an unusual successful login",
    }.get(behavior, "observed in intelligence data")
    return (f"{name}: {indicator_type.replace('_', ' ').lower()} indicator {behavior_text}. "
            f"Indicator match alone does not confirm compromise. [{DATA_LABEL}]")


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------
PRODUCT_CATEGORIES = ["Web Server", "VPN Gateway", "Email Server", "Web Browser", "Office Suite",
                      "Operating System", "Database", "CMS Plugin", "Network Firewall",
                      "Container Runtime", "Identity Provider", "IoT Camera"]
VULN_TYPES = ["input-validation weakness", "authentication bypass weakness", "memory-safety weakness",
              "access-control weakness", "information-disclosure weakness", "configuration weakness"]


def generate_vulnerabilities(count: int = 60, seed: int = 42, reference_date: date | None = None) -> list[dict]:
    rng = random.Random(seed + 1)
    ref = reference_date or date.today()
    rows = []

    def build(cve_id, product, cvss, published, patch, exploit, asset, exposure, sensitive, text):
        p = calculate_vulnerability_priority(cvss, asset, exposure, exploit, sensitive, patch)
        return {
            "cve_id": cve_id, "product_category": product, "severity": cvss_severity(cvss),
            "cvss_score": cvss, "published_date": published.isoformat(), "patch_available": int(patch),
            "exploitation_status_demo": exploit, "asset_criticality": asset, "exposure": exposure,
            "handles_sensitive_data": int(sensitive), "priority_score": p["priority_score"],
            "priority_band": p["priority_band"], "description": f"{text} [{DATA_LABEL}]",
            "data_label": DATA_LABEL,
        }

    # Two hand-crafted records that demonstrate contextual prioritisation.
    rows.append(build("CVE-2099-0001", "Operating System", 9.8, ref - timedelta(days=40), True,
                      "NO_KNOWN_EXPLOITATION", "LOW", "ISOLATED", False,
                      "Critical CVSS memory-safety weakness in a fictional OS, found on an isolated test "
                      "machine with no network exposure."))
    rows.append(build("CVE-2099-0002", "VPN Gateway", 8.1, ref - timedelta(days=12), True,
                      "EXPLOITATION_REPORTED_DEMO", "CRITICAL", "INTERNET_FACING", True,
                      "High CVSS authentication weakness in a fictional VPN gateway that is internet-facing "
                      "and protects critical systems."))
    for i in range(count):
        cvss = round(min(10.0, max(2.0, rng.gauss(7.0, 1.7))), 1)
        product = rng.choice(PRODUCT_CATEGORIES)
        rows.append(build(
            f"CVE-2099-{10001 + i}", product, cvss, ref - timedelta(days=rng.randint(1, 365)),
            rng.random() < 0.8,
            wchoice(rng, {"NO_KNOWN_EXPLOITATION": 6, "PUBLIC_POC_DEMO": 3, "EXPLOITATION_REPORTED_DEMO": 1}),
            wchoice(rng, {"LOW": 2, "MEDIUM": 4, "HIGH": 3, "CRITICAL": 1}),
            wchoice(rng, {"ISOLATED": 1, "INTERNAL": 5, "INTERNET_FACING": 3}),
            rng.random() < 0.3,
            f"Synthetic {rng.choice(VULN_TYPES)} in a fictional {product.lower()} product.",
        ))
    return rows


# ---------------------------------------------------------------------------
# Threat records
# ---------------------------------------------------------------------------
def _demo_records(ref: date, year: int) -> list[dict]:
    """The fixed demonstration scenario (see docs/DEMO_SCENARIO.md)."""
    base = {
        "threat_category": "PHISHING", "source_name": "Security Vendor", "impact_level": "HIGH",
        "first_seen": (ref - timedelta(days=20)).isoformat(), "last_seen": (ref - timedelta(days=2)).isoformat(),
        "observation_count": 5, "campaign_id": "CMP-DEMO-001", "country_or_region_optional": "Europe",
        "behavior_observed": "email_link_lure", "cve_id_optional": "", "_corroborating": 3,
        "_analyst_verified": True,
    }
    return [
        dict(base, threat_id=f"THR-{year}-001", threat_name="Synthetic Credential Phishing Campaign",
             indicator_type="DOMAIN", indicator_value="login-check.invalid", status="MONITORING",
             description="Synthetic credential-phishing campaign: domain login-check.invalid appeared in "
                         "multiple synthetic phishing emails linking to a fake sign-in page. "
                         f"Indicator match alone does not confirm compromise. [{DATA_LABEL}]"),
        dict(base, threat_id=f"THR-{year}-002", threat_name="Synthetic Phishing Infrastructure Host",
             indicator_type="IP", indicator_value="198.51.100.25", status="MONITORING",
             description="Documentation-range IP 198.51.100.25 hosted the synthetic phishing domain "
                         f"login-check.invalid. [{DATA_LABEL}]"),
        dict(base, threat_id=f"THR-{year}-003", threat_name="Synthetic Credential Phishing Lure URL",
             indicator_type="URL", indicator_value="https://login-check.invalid/verify/session",
             status="UNDER_REVIEW", observation_count=3, _corroborating=1, _analyst_verified=False,
             description=f"Lure URL on the synthetic phishing domain. Never visit this URL. [{DATA_LABEL}]"),
        dict(base, threat_id=f"THR-{year}-004", threat_name="Synthetic Phishing Sender Address",
             indicator_type="EMAIL", indicator_value="security-alert@login-check.invalid",
             status="MONITORING", observation_count=9, _corroborating=2, _analyst_verified=True,
             source_name="Internal SOC",
             description=f"Sender address used in the synthetic phishing campaign emails. [{DATA_LABEL}]"),
    ]


def generate_threat_records(count: int = 2000, seed: int = 42, reference_date: date | None = None,
                            cve_ids: list[str] | None = None) -> list[dict]:
    """Generate `count` synthetic records plus the 4 fixed demo-scenario records."""
    rng = random.Random(seed)
    ref = reference_date or date.today()
    year = ref.year
    cve_ids = cve_ids or [f"CVE-2099-{10001 + i}" for i in range(60)]
    records = _demo_records(ref, year)
    reserved = {r["indicator_value"] for r in records} | {"203.0.113.77"}
    factory = IndicatorFactory(rng, cve_ids, reserved)
    categories = {c: p["weight"] for c, p in CATEGORY_PROFILES.items()}

    # --- 1. Campaigns: groups of records sharing infrastructure --------------
    campaigns = []
    for i in range(max(1, count // 16)):
        cat = wchoice(rng, categories)
        prof = CATEGORY_PROFILES[cat]
        start = ref - timedelta(days=rng.randint(5, 180))
        pool = [(t, factory.make(t)) for t in (wchoice(rng, prof["types"]) for _ in range(rng.randint(2, 6)))]
        campaigns.append({
            "id": f"CMP-{year}-{i + 1:03d}", "category": cat, "start": start,
            "end": min(ref, start + timedelta(days=rng.randint(3, 45))),
            "name": f"{rng.choice(CODENAME_A)} {rng.choice(CODENAME_B)}",
            "pool": pool, "source": wchoice(rng, SOURCE_WEIGHTS),
        })

    # --- 2. Individual records ------------------------------------------------
    for n in range(count):
        in_campaign = rng.random() < 0.55
        camp = rng.choice(campaigns) if in_campaign else None
        cat = camp["category"] if camp else wchoice(rng, categories)
        prof = CATEGORY_PROFILES[cat]
        if camp:
            itype, ivalue = rng.choice(camp["pool"])
            span = max(0, (camp["end"] - camp["start"]).days)
            first = camp["start"] + timedelta(days=rng.randint(0, span))
            name = f"Synthetic {camp['name']} {rng.choice(prof['names'])}"
            source = camp["source"] if rng.random() < 0.6 else wchoice(rng, SOURCE_WEIGHTS)
        else:
            itype = wchoice(rng, prof["types"])
            ivalue = factory.make(itype)
            first = ref - timedelta(days=rng.randint(0, 180))
            name = f"Synthetic {rng.choice(prof['names'])}"
            source = wchoice(rng, SOURCE_WEIGHTS)
        last = min(ref, first + timedelta(days=int(rng.expovariate(1 / 6))))
        age = (ref - last).days
        if age > 90:
            status = wchoice(rng, {"CLOSED": 55, "FALSE_POSITIVE": 15, "MONITORING": 20, "UNDER_REVIEW": 10})
        else:
            status = wchoice(rng, {"NEW": 25, "UNDER_REVIEW": 25, "MONITORING": 30, "CLOSED": 10,
                                   "FALSE_POSITIVE": 10})
        behavior = wchoice(rng, prof["behaviors"])
        cve = ""
        if itype == "CVE":
            cve = ivalue
        elif cat == "VULNERABILITY_EXPOSURE" or (behavior == "public_app_exploit_attempt" and rng.random() < 0.4):
            cve = factory.cve()
        records.append({
            "threat_id": f"THR-{year}-{n + 5:03d}",
            "threat_name": name,
            "threat_category": cat,
            "indicator_type": itype,
            "indicator_value": ivalue,
            "source_name": source,
            "impact_level": wchoice(rng, prof["impact"]),
            "first_seen": first.isoformat(),
            "last_seen": last.isoformat(),
            "observation_count": min(400, int(rng.paretovariate(1.1))),
            "campaign_id": camp["id"] if camp else "",
            "country_or_region_optional": "" if rng.random() < 0.15 else rng.choice(REGIONS),
            "behavior_observed": behavior,
            "cve_id_optional": cve,
            "status": status,
            "description": describe(cat, behavior, itype, name),
            "_corroborating": (1 if camp else 0) + wchoice(rng, {0: 5, 1: 3, 2: 2}) if status != "FALSE_POSITIVE" else 0,
            "_analyst_verified": status in ("MONITORING", "CLOSED", "UNDER_REVIEW") and rng.random() < 0.6,
        })

    # A deliberate burst: one scanning IP observed very frequently (alert-correlation demo).
    burst = records[-1]
    burst.update(threat_category="NETWORK_THREATS", indicator_type="IP", indicator_value="203.0.113.77",
                 threat_name="Synthetic High-Volume Scanning Source", behavior_observed="external_scanning",
                 observation_count=100, status="NEW", impact_level="MEDIUM", campaign_id="",
                 first_seen=(ref - timedelta(days=1)).isoformat(), last_seen=ref.isoformat(), cve_id_optional="",
                 description=describe("NETWORK_THREATS", "external_scanning", "IP",
                                      "Synthetic High-Volume Scanning Source"))

    # --- 3. Correlation counts (shared campaign or shared indicator) ----------
    by_campaign, by_indicator = {}, {}
    for r in records:
        if r["campaign_id"]:
            by_campaign.setdefault(r["campaign_id"], set()).add(r["threat_id"])
        by_indicator.setdefault(r["indicator_value"], set()).add(r["threat_id"])

    # --- 4. Scoring + ATT&CK mapping -----------------------------------------
    for r in records:
        related = set(by_indicator[r["indicator_value"]])
        if r["campaign_id"]:
            related |= by_campaign[r["campaign_id"]]
        related.discard(r["threat_id"])
        grade = INTEL_SOURCES[r["source_name"]]["reliability"]
        mapping = map_to_attack(r["behavior_observed"])
        age = days_since(r["last_seen"], ref)
        confidence = calculate_confidence(
            source_reliability=grade,
            corroborating_sources=r.pop("_corroborating"),
            validated=True,
            has_context=r["behavior_observed"] != "reputation_only",
            analyst_verified=r.pop("_analyst_verified"),
            days_since_last_seen=age,
        )
        risk = calculate_threat_risk(
            severity=r["impact_level"], confidence=confidence, last_seen=r["last_seen"],
            observation_count=r["observation_count"], source_reliability=grade,
            correlated_indicators=min(5, len(related)), has_attack_mapping=mapping is not None,
            has_cve=bool(r["cve_id_optional"]), reference_date=ref,
        )
        hour, minute = rng.randint(0, 23), rng.randint(0, 59)
        r.update({
            "timestamp": f"{r['last_seen']}T{hour:02d}:{minute:02d}:00",
            "source_reliability": grade,
            "confidence_score": confidence,
            "risk_score": risk["risk_score"],
            "severity": risk["classification"],
            "mitre_tactic_optional": mapping["tactic"] if mapping else "",
            "mitre_technique_optional": mapping["technique"] if mapping else "",
            "mitre_technique_id_optional": mapping["technique_id_optional"] if mapping else "",
            "data_label": DATA_LABEL,
        })
    return records


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate SYNTHETIC threat-intelligence demo data.")
    parser.add_argument("--count", type=int, default=2000, help="number of generated threat records")
    parser.add_argument("--vulns", type=int, default=60, help="number of generated vulnerability records")
    parser.add_argument("--seed", type=int, default=42, help="random seed (same seed = same data)")
    parser.add_argument("--reference-date", type=str, default=None,
                        help="'today' for the dataset (YYYY-MM-DD). Defaults to the real today.")
    parser.add_argument("--out-dir", type=str, default=str(ROOT / "data"))
    args = parser.parse_args(argv)

    ref = date.fromisoformat(args.reference_date) if args.reference_date else date.today()
    out = Path(args.out_dir)
    vulns = generate_vulnerabilities(args.vulns, args.seed, ref)
    threats = generate_threat_records(args.count, args.seed, ref,
                                      cve_ids=[v["cve_id"] for v in vulns[2:]])
    write_csv(out / "threat_intelligence_dataset.csv", threats, THREAT_FIELDS)
    write_csv(out / "vulnerabilities.csv", vulns, VULN_FIELDS)

    from collections import Counter
    sev = Counter(r["severity"] for r in threats)
    print(f"[+] Wrote {len(threats)} threat records -> {out / 'threat_intelligence_dataset.csv'}")
    print(f"[+] Wrote {len(vulns)} vulnerability records -> {out / 'vulnerabilities.csv'}")
    print("[i] Severity mix:", dict(sorted(sev.items())))
    print(f"[i] Reference date: {ref.isoformat()}   Label: {DATA_LABEL}")
    demo = threats[0]
    print(f"[i] Demo record {demo['threat_id']}: risk={demo['risk_score']} confidence={demo['confidence_score']}"
          f" severity={demo['severity']}")


if __name__ == "__main__":
    main()
