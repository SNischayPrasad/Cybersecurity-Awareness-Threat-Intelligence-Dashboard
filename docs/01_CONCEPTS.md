# 01 · Core Concepts (read this first)

This guide explains every concept the project uses. Each concept has two versions:
**A. Simple explanation** (as if explaining to a friend) and **B. Technical explanation** (how you'd say it in an interview).

---

## 1. Project explanation — the 15 key terms

### Cybersecurity awareness
- **A. Simple:** Teaching people to spot and avoid tricks such as fake emails, weak passwords and scam calls.
- **B. Technical:** A continuous programme that reduces human-layer risk through training, simulations, just-in-time guidance and clear reporting channels. It is measured through behaviour metrics (report rates, click rates) and knowledge checks, not just course completion.

### Cyber threat intelligence (CTI)
- **A. Simple:** Collecting information about "bad guys" and their tools so defenders can prepare.
- **B. Technical:** Evidence-based knowledge (context, mechanisms, indicators, implications, advice) about existing or emerging threats, produced through a lifecycle (direction → collection → processing → analysis → dissemination → feedback) to support defensive decisions.

### IOC (Indicator of Compromise)
- **A. Simple:** A clue left behind by an attack, like a fingerprint, such as a bad web address or a known malicious file.
- **B. Technical:** An observable artifact (IP, domain, URL, file hash, email sender, registry key…) that, with context, suggests malicious activity. IOCs are *atomic* or *computed* and sit at the bottom of the "Pyramid of Pain": cheap for adversaries to change.

### IOA (Indicator of Attack)
- **A. Simple:** A sign that an attack is *happening*, based on what someone is doing rather than what they left behind.
- **B. Technical:** A behavioural pattern (e.g., Office spawning a script interpreter, mass file renames, MFA push floods) that shows adversary intent regardless of the specific tooling. IOAs are more durable than IOCs because behaviours are harder to change than infrastructure.

### Vulnerability
- **A. Simple:** A weak spot in software, like an unlocked window in a house.
- **B. Technical:** A weakness in software, hardware, configuration or process that could be exploited to violate confidentiality, integrity or availability.

### CVE (Common Vulnerabilities and Exposures)
- **A. Simple:** A public ID number for a known vulnerability, so everyone talks about the same bug.
- **B. Technical:** A standardised identifier (`CVE-YYYY-NNNN+`) assigned by CVE Numbering Authorities, coordinated by the CVE Program. *This project uses fake `CVE-2099-*` IDs so no synthetic record is confused with a real CVE.*

### CVSS (Common Vulnerability Scoring System)
- **A. Simple:** A 0–10 score for how bad a vulnerability is in general.
- **B. Technical:** A FIRST-maintained framework that scores exploitability and impact metrics (base score), optionally adjusted by threat and environmental metrics. Qualitative bands (v3): None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0. The base score does **not** know your environment.

### Threat feed
- **A. Simple:** A regularly updated list of known-bad things (addresses, files) shared by security teams.
- **B. Technical:** A machine-readable stream of indicators and context (often via STIX/TAXII, CSV or JSON APIs) from internal, commercial, open-source or community sources. Feeds vary in quality, timeliness and false-positive rate, which is why this project scores **source reliability**.

### Threat actor (conceptually)
- **A. Simple:** The person or group behind an attack.
- **B. Technical:** An entity with intent and capability to cause harm, such as cybercriminals, state-sponsored groups, hacktivists or insiders. **This project deliberately performs no attribution**: correlation shows related evidence, not who is responsible.

### TTP (Tactics, Techniques and Procedures)
- **A. Simple:** *How* attackers usually work: their goals, methods and habits.
- **B. Technical:** Tactics = adversary goals; techniques = the means to achieve them; procedures = the specific implementations. TTPs sit at the top of the Pyramid of Pain: hardest for adversaries to change and most valuable for defenders to detect.

### MITRE ATT&CK
- **A. Simple:** A big public encyclopedia of attacker behaviours, organised by goal.
- **B. Technical:** A globally accessible knowledge base of adversary tactics and techniques based on real-world observations, organised into matrices (Enterprise, Mobile, ICS). Used for detection engineering, gap analysis, threat-intel tagging and red/blue team communication.

### Threat enrichment
- **A. Simple:** Adding background information to a clue so you understand it better.
- **B. Technical:** Augmenting a raw indicator with context such as first/last seen, related infrastructure, categories, confidence, ATT&CK mapping, related alerts and analyst notes. **Here, enrichment uses only the local database**; no WHOIS, DNS or HTTP lookups are made.

### Threat correlation
- **A. Simple:** Connecting clues that belong together.
- **B. Technical:** Linking records that share evidence (same campaign, same indicator, overlapping time windows) into clusters so analysts see one picture instead of many fragments. Correlation ≠ attribution.

### Threat hunting
- **A. Simple:** Actively looking for hidden attackers instead of waiting for an alarm.
- **B. Technical:** A hypothesis-driven, analyst-led search through telemetry for adversary activity that evaded automated detection, often guided by CTI and ATT&CK techniques. Outputs are new detections and improved visibility.

### SOC (Security Operations Center)
- **A. Simple:** The security "control room" that watches for and responds to attacks.
- **B. Technical:** A team, process and technology function (SIEM, EDR, SOAR, ticketing) that provides continuous monitoring, triage, investigation, incident response coordination and reporting, typically tiered (Tier 1 triage → Tier 2 investigation → Tier 3/IR and hunting).

---

## 1b. The complete workflow

```
Threat Data / Synthetic Feed        data/generate_threat_data.py -> CSV
        ↓
Data Collection                     ingestion.py (pandas.read_csv)
        ↓
Normalization                       threat_service.normalize_threat_input()
        ↓
Validation                          ioc_validator.validate_indicator()
        ↓
IOC Extraction                      primary indicator -> indicators table
        ↓
Threat Classification               category + behaviour
        ↓
Risk / Severity Scoring             risk_engine.calculate_threat_risk() + calculate_confidence()
        ↓
MITRE ATT&CK Mapping (if justified) attack_mapper.map_to_attack()
        ↓
Threat Database                     SQLite (backend/models/schema.sql)
        ↓
Correlation                         correlation_engine.correlate_threats()
        ↓
Alerts                              alert_engine.generate_*_alert() + correlate_alerts()
        ↓
SOC Dashboard                       frontend/threat-dashboard.html (+ details, ATT&CK, alerts)
        ↓
Security Awareness Module           frontend/awareness.html + quiz.html
        ↓
Analyst / User
```

**Evidence ladder: the dashboard never labels every suspicious item as an attack.**

| Level | Meaning in this project |
|---|---|
| **OBSERVATION** | A raw sighting (the `observation_count` on a record). |
| **INDICATOR** | A syntactically valid artifact with context (a row in `indicators`). |
| **ALERT** | A rule fired: risk/confidence thresholds, repetition, correlation, or vulnerability priority. |
| **THREAT** | Triage judged it credible and relevant (status UNDER_REVIEW/MONITORING and risk ≥ 61). |
| **INCIDENT** | Confirmed impact, declared by an analyst. **Zero in the demo data, on purpose.** |

---

## 2. Cybersecurity awareness vs. threat intelligence

| | Cybersecurity awareness | Threat intelligence |
|---|---|---|
| Goal | Help **people** recognise and avoid risk | Help **defenders** make decisions |
| Audience | Everyone (staff, students, executives) | SOC, IR, vulnerability and security engineering teams |
| Examples | Phishing awareness, passwords, MFA, safe browsing, social engineering, updates, secure Wi-Fi, privacy, suspicious attachments, reporting incidents | IOCs, TTPs, campaign tracking, vulnerability exploitation evidence |
| Output | Behaviour change, faster reporting | Detections, blocks, priorities, reports |

**How this project combines them (HUMAN DEFENSE + TECHNICAL INTELLIGENCE):**
- Every threat category links to an awareness module (e.g., a phishing record links to *Phishing Awareness*).
- The executive summary shows threat trends **and** awareness trends side by side, so leaders see that the most common active threat (phishing) matches a weak awareness area.
- Quiz weaknesses become learning recommendations, and SOC findings become awareness content. It is a feedback loop.

---

## 3. Industry relevance

| Sector | Why a threat-intel + awareness dashboard matters |
|---|---|
| Security Operations Centers | Prioritise alerts, reduce fatigue, speed up triage with enrichment. |
| Banks | Phishing, credential theft and payment fraud; regulators expect threat-informed defence and staff training. |
| Cloud companies | Huge attack surface; correlating indicators across tenants; account-takeover defence. |
| IT enterprises | Ransomware and phishing are top risks; vulnerability prioritisation across thousands of assets. |
| Government | Sector-sharing (ISACs/CERTs), advisories, known-exploited vulnerability tracking. |
| E-commerce | Credential stuffing, web threats, payment skimming, customer-facing phishing. |
| Healthcare | Ransomware disrupts patient care; strict privacy obligations. |
| Universities | Open networks, many users, research data; phishing-heavy environment. |
| MSSPs | Must triage many clients' alerts efficiently: correlation and scoring are core. |
| Cybersecurity consulting | Threat-informed assessments, awareness programmes, executive reporting. |

**Roles and the skills this project demonstrates**

| Role | What they do | Where this project shows it |
|---|---|---|
| SOC Analyst | Monitor, triage, escalate alerts | Alert queue, statuses, analyst notes, SOC workflow |
| Cybersecurity Analyst | Analyse risk and controls | Risk vs confidence, recommended defensive actions |
| Threat Intelligence Analyst | Collect, evaluate, correlate intel | Source reliability, enrichment, correlation clusters, ATT&CK |
| Incident Response Analyst | Contain and recover from incidents | Evidence ladder, IR lifecycle & checklist, timeline |
| Security Engineer | Build secure systems/tooling | Flask API, RBAC, CSP, input validation, rate limiting, tests |
| Vulnerability Analyst | Prioritise remediation | Contextual vulnerability priority (CVSS + context) |
| Security Awareness Specialist | Train people | 15 modules, 40-question quiz, recommendations |
| Threat Hunter | Search for undetected threats | ATT&CK technique pivot → records, IOC search |

---

## 4. Threat-intelligence types

| Type | Audience | Question it answers | Simple example |
|---|---|---|---|
| **Strategic** | Executives, board | "What threats matter to our business?" | "Ransomware against healthcare rose this year; invest in backups." |
| **Tactical** | Security architects, SOC leads | "How do attackers operate?" (TTPs) | "Phishing campaigns use QR codes to bypass link scanning." |
| **Operational** | IR, hunters | "What specific campaign is coming, and when?" | "A campaign targeting our sector's VPNs is active this week." |
| **Technical** | SOC tools, analysts | "Which exact artifacts should we look for?" | "Block domain `login-check.invalid`; hash `abc…`." |

**This student project focuses on Technical + Tactical + Awareness-oriented intelligence:** IOCs and their scoring (technical), ATT&CK behaviours (tactical), and turning both into human guidance (awareness). The executive page gives a small taste of strategic reporting.

---

## 6. IOCs and their limitations

Possible IOC types here: **IP address, domain, URL, file hash, email sender/domain** (plus **CVE IDs** as vulnerability references).

**Important limitation:** an IOC can go **stale** (infrastructure is abandoned or re-assigned), can be **shared by benign infrastructure** (cloud hosting, CDNs, NAT gateways), or can **lack context** (no idea why it was listed). Therefore:

> **IOC MATCH ≠ AUTOMATIC CONFIRMED COMPROMISE**

**IOC lifecycle used in this project**

```
Observed      -> FIRST_SEEN timeline event
   ↓
Validated     -> validate_indicator(): syntax only
   ↓
Enriched      -> enrich_indicator(): local context
   ↓
Scored        -> risk + confidence
   ↓
Investigated  -> status UNDER_REVIEW, analyst notes
   ↓
Monitored     -> status MONITORING
   ↓
Expired/Closed-> status CLOSED or FALSE_POSITIVE (recency decay lowers risk over time)
```

---

## 10–11. Risk vs. confidence

| Score | Question | Inputs |
|---|---|---|
| **Risk (0–100)** | How concerning could this be? | Severity 30%, Confidence 25%, Recency 15%, Frequency 10%, Source reliability 10%, Context/correlation 10% |
| **Confidence (0–100)** | How much do we trust this intelligence? | Source grade base, corroborating sources, validation, behavioural context, analyst review, staleness penalty |

Bands: 0–20 INFORMATIONAL · 21–40 LOW · 41–60 MEDIUM · 61–80 HIGH · 81–100 CRITICAL.

| Example | Interpretation |
|---|---|
| Risk 90 · Confidence 25 | Potentially serious, but evidence quality is weak. Validate before acting. |
| Risk 70 · Confidence 95 | High-confidence intelligence with meaningful risk. Prioritise triage. |

**High risk does NOT automatically mean confirmed compromise.** It means "look at this first".

Worked example (the demo record): HIGH impact (80×0.30=24) + confidence 85 (×0.25=21.25) + seen 2 days ago (100×0.15=15) + 5 sightings (52×0.10=5.2) + Security Vendor grade B (75×0.10=7.5) + 3 correlated indicators and an ATT&CK mapping (50×0.10=5) = **77.95 → 78 (HIGH)**.

## 12. Source reliability

| Grade | Label | Synthetic sources |
|---|---|---|
| A | Highly Reliable | Internal SOC |
| B | Usually Reliable | Security Vendor, Research Report |
| C | Fairly Reliable | Public Threat Feed, Community Submission |
| D | Reliability Unknown | Unknown Source |

**Reliability ≠ confidence.** Reliability is about the *source's track record*; confidence is about *this specific item*. A highly reliable source can still pass on an item it isn't sure about, and an unknown source's item can gain confidence once three other sources corroborate it.

## 13. Threat categories

See `backend/services/threat_categories.py` (also served at `GET /api/categories`). Each category includes description, common indicators, potential impact, defensive controls and awareness recommendations:
Phishing · Malware · Ransomware · Credential Theft · Social Engineering · Network Threats · Web Threats · Data Exposure · Account Takeover Risk · Vulnerability Exploitation Awareness. No exploitation instructions are included anywhere.

## 14. MITRE ATT&CK in this project

- **Tactic** = *why* (the adversary's goal, e.g., Initial Access).
- **Technique** = *how* (e.g., T1566 Phishing).
- **Sub-technique** = a more specific *how* (e.g., T1566.002 Spearphishing Link).

Records are mapped **only when a behaviour was observed** (`behavior_observed`). A record that is only "on a reputation feed" stays **unmapped** (about 28% of the dataset), because an indicator by itself is not a behaviour. IDs used (Enterprise ATT&CK, v15+ naming) include T1566.001/.002/.004, T1598.003, T1204.002, T1071.001, T1105, T1547.001, T1486, T1490, T1110/.003, T1621, T1078, T1539, T1190, T1189, T1595, T1133, T1498, T1530, T1567, T1041 and T1656. Verify at attack.mitre.org before production use.

> IOC tells us **WHAT** artifact was observed. ATT&CK helps describe **HOW** the behaviour relates to adversary techniques.

## 16–17. Vulnerabilities, exploits, zero-days and prioritisation

- **Vulnerability:** a weakness. **Patch:** a vendor fix. **Exploit (conceptually):** a method or code that abuses a vulnerability. **Zero-day (conceptually):** a vulnerability exploited before a fix is available.
- **Why CVSS alone isn't enough:** CVSS measures generic severity. Real priority depends on *your* context:

```
CVSS + Asset Criticality + Exposure + Known Exploitation Evidence + Business Context = Better Prioritisation
```

`calculate_vulnerability_priority()` weights CVSS 35%, asset criticality 25%, exposure 20% and exploitation evidence 20%, plus 5 points for sensitive data. The demo contrasts:
- `CVE-2099-0001`: CVSS **9.8** on an isolated, low-criticality test machine → **44.5 (P3)**
- `CVE-2099-0002`: CVSS **8.1** on an internet-facing, critical VPN gateway with reported exploitation → **98.3 (P1)**

This mirrors real-world practice such as prioritising known-exploited vulnerabilities (e.g., CISA KEV) and exploitation-probability models (e.g., EPSS).
