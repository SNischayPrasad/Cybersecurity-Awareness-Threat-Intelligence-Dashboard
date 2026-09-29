"""
Threat Enrichment Engine
========================

enrich_indicator() adds context to a raw indicator using ONLY the local
database. It never performs DNS lookups, WHOIS, HTTP requests or any other
network activity - the searched value is treated purely as data.

Future (optional, authorised) integrations could add passive DNS, WHOIS age,
sandbox verdicts or vendor reputation via approved APIs - but the project is
designed to work fully offline.
"""
from __future__ import annotations

import ipaddress

from backend.services.attack_mapper import attack_technique_url
from backend.services.ioc_validator import defang, is_documentation_ip, is_reserved_domain, validate_indicator
from backend.services.risk_engine import interpret_risk_confidence
from backend.services.threat_categories import THREAT_CATEGORIES

SEV_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def local_context(validation: dict) -> list[str]:
    """Offline facts derivable from the value itself."""
    facts = []
    itype, value = validation["indicator_type"], validation["normalized_value"]
    if itype == "IP":
        ip = ipaddress.ip_address(value)
        facts.append(f"IP version: IPv{ip.version}")
        if is_documentation_ip(ip):
            facts.append("Documentation range - reserved for examples, never routed on the internet.")
        elif ip.is_private:
            facts.append("Private range - likely an internal asset; check your own inventory first.")
        facts.append("Shared-infrastructure caution: one IP can serve many unrelated customers (cloud/CDN/NAT).")
    elif itype == "DOMAIN":
        facts.append(f"Top-level domain: .{value.rsplit('.', 1)[-1]}")
        facts.append(f"Label count: {value.count('.') + 1}")
        if is_reserved_domain(value):
            facts.append("Reserved documentation/testing domain.")
        facts.append("Domains can change ownership; old intelligence may no longer apply.")
    elif itype == "URL":
        facts.append("URL host and path analysed as text only. The URL was not visited.")
    elif itype == "FILE_HASH":
        facts.append(f"Hash algorithm (by length): {validation.get('subtype')}")
        facts.append("A hash identifies a specific file; any byte change produces a different hash.")
    elif itype == "EMAIL":
        facts.append(f"Sender domain: {value.split('@', 1)[1]}")
        facts.append("Sender addresses are easy to spoof; check SPF/DKIM/DMARC results in mail logs.")
    elif itype == "CVE":
        facts.append("CVE IDs identify a vulnerability, not an attack. See vulnerability priority.")
    return facts


def enrich_indicator(conn, raw_value: str) -> dict:
    """Validate + enrich an indicator from local synthetic intelligence."""
    validation = validate_indicator(raw_value)
    result = {
        "query": raw_value,
        "validation": validation,
        "network_activity": "NONE - database lookup only. The indicator was not contacted.",
        "known_in_dataset": False,
    }
    if not validation["valid"]:
        result["message"] = "Indicator is not syntactically valid, so it was not looked up."
        return result

    value = validation["normalized_value"]
    itype = validation["indicator_type"]
    result.update(indicator_type=itype, subtype=validation.get("subtype"), normalized_value=value,
                  defanged=defang(value), local_context=local_context(validation))

    rows = [dict(r) for r in conn.execute(
        """SELECT DISTINCT t.threat_id, t.threat_name, t.category, t.severity, t.risk_score, t.confidence_score,
                  t.status, t.first_seen, t.last_seen, t.observation_count, t.campaign_id, s.source_name,
                  s.reliability
           FROM indicators i JOIN threats t ON t.threat_id = i.threat_id
           LEFT JOIN sources s ON s.source_id = t.source_id
           WHERE i.normalized_value = ? ORDER BY t.risk_score DESC""", (value.lower(),))]

    # CVE indicators may also exist only in the vulnerability table.
    vuln = None
    if itype == "CVE":
        v = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (value,)).fetchone()
        vuln = dict(v) if v else None
        if not rows:
            rows = [dict(r) for r in conn.execute(
                "SELECT t.threat_id, t.threat_name, t.category, t.severity, t.risk_score, t.confidence_score, "
                "t.status, t.first_seen, t.last_seen, t.observation_count, t.campaign_id, s.source_name, "
                "s.reliability FROM threats t LEFT JOIN sources s ON s.source_id=t.source_id "
                "WHERE t.cve_id = ? ORDER BY t.risk_score DESC", (value,))]
    result["vulnerability"] = vuln

    if not rows:
        result["message"] = ("Not found in the local dataset. Absence of intelligence is NOT evidence that "
                             "the indicator is safe.")
        result["known_in_dataset"] = bool(vuln)
        return result

    ids = [r["threat_id"] for r in rows]
    top = rows[0]
    marks = ",".join("?" * len(ids))
    campaigns = sorted({r["campaign_id"] for r in rows if r["campaign_id"]})

    related_indicators = []
    if campaigns:
        related_indicators = [dict(r) for r in conn.execute(
            f"""SELECT DISTINCT i.indicator_type, i.indicator_value, t.threat_id FROM indicators i
                JOIN threats t ON t.threat_id = i.threat_id
                WHERE t.campaign_id IN ({','.join('?' * len(campaigns))}) AND i.normalized_value != ?
                LIMIT 25""", campaigns + [value.lower()])]
    related_indicators += [dict(r) for r in conn.execute(
        f"SELECT indicator_type, indicator_value, threat_id FROM indicators WHERE threat_id IN ({marks}) "
        f"AND normalized_value != ? AND is_primary = 0", ids + [value.lower()])]
    for r in related_indicators:
        r["defanged"] = defang(r["indicator_value"])

    alerts = [dict(r) for r in conn.execute(
        f"SELECT alert_id, alert_type, severity, status, observation_count FROM alerts "
        f"WHERE threat_id IN ({marks}) OR indicator_value = ? ORDER BY created_at DESC LIMIT 20",
        ids + [value])]
    mappings = [dict(r, reference_url=attack_technique_url(r["technique_id_optional"])) for r in conn.execute(
        f"SELECT DISTINCT tactic, technique, technique_id_optional FROM attack_mappings WHERE threat_id IN ({marks})",
        ids)]
    notes = [dict(r) for r in conn.execute(
        f"SELECT threat_id, author, note, created_at FROM analyst_notes WHERE threat_id IN ({marks}) "
        f"ORDER BY note_id DESC LIMIT 10", ids)]

    result.update({
        "known_in_dataset": True,
        "record_count": len(rows),
        "first_seen": min(r["first_seen"] for r in rows),
        "last_seen": max(r["last_seen"] for r in rows),
        "total_observations": sum(r["observation_count"] for r in rows),
        "associated_categories": sorted({r["category"] for r in rows}),
        "associated_category_labels": sorted({THREAT_CATEGORIES[r["category"]]["label"] for r in rows}),
        "severity": max((r["severity"] for r in rows), key=lambda s: SEV_RANK[s]),
        "risk_score": top["risk_score"],
        "confidence_score": top["confidence_score"],
        "status": top["status"],
        "primary_threat_id": top["threat_id"],
        "sources": sorted({f"{r['source_name']} ({r['reliability']})" for r in rows if r["source_name"]}),
        "campaigns": campaigns,
        "threat_records": rows[:25],
        "related_indicators": related_indicators[:25],
        "related_alerts": alerts,
        "attack_mappings": mappings,
        "analyst_notes": notes,
        "interpretation": interpret_risk_confidence(top["risk_score"], top["confidence_score"]),
        "caution": "IOC match does not equal confirmed compromise. Check context, age and source before acting.",
    })
    return result
