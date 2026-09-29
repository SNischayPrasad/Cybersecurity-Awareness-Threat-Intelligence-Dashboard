# Cybersecurity Awareness & Threat Intelligence Dashboard: Project Report

**Course:** Cybersecurity · **Type:** Defensive security project · **Data:** 100% synthetic
**Author:** Sadhanala Nischay Prasad · **Repository:** `Cybersecurity-Awareness-Threat-Intelligence-Dashboard`

---

## Abstract
Organisations face two linked problems: security teams are overwhelmed by threat indicators of uneven quality, and people remain the most frequently targeted entry point. This project presents a defensive web platform that addresses both. A synthetic feed of 2,004 threat records (IPs, domains, URLs, file hashes, email senders and CVE references, all drawn from reserved or synthetic ranges) is normalised, syntactically validated, enriched from a local database, scored separately for **risk** and **confidence**, graded by **source reliability**, mapped to **MITRE ATT&CK** only when behaviour justifies it, correlated into related clusters, and turned into de-duplicated alerts. A SOC-style dashboard provides KPIs, ten charts, IOC search, filtering, an investigation view with timelines and analyst notes, an ATT&CK drill-down and an alert queue. A contextual vulnerability module shows why CVSS alone is insufficient. In parallel, an Awareness Center with 15 modules and a 40-question quiz produces category scores and personalised learning recommendations, and an executive summary translates everything into plain language. The system never contacts an indicator. It is implemented in Python (Flask, SQLite, pandas) and JavaScript (Chart.js), secured with RBAC, audit logging, CSP and input validation, and verified by 40 automated tests.

## 1. Introduction
Cyber threat intelligence (CTI) helps defenders anticipate and detect attacks, but raw indicators are only useful with context: how recent, how reliable, how related and how relevant. Meanwhile, phishing and social engineering continue to exploit human behaviour. This project combines **technical threat intelligence** with **cybersecurity awareness** in one educational platform.

## 2. Problem Statement
1. Analysts receive large volumes of indicators with no consistent way to judge how *concerning* versus how *trustworthy* each one is.
2. Duplicate and related alerts cause alert fatigue.
3. Vulnerability patching is often prioritised by CVSS alone, ignoring exposure and exploitation.
4. Indicator matches are frequently mistaken for confirmed compromises.
5. Awareness training is disconnected from the threats the organisation actually sees.

## 3. Objectives
- Generate a safe, realistic synthetic intelligence dataset (≥ 2,000 records).
- Validate IOC syntax without ever contacting indicators.
- Implement separate risk and confidence scoring with source reliability.
- Map behaviours (not bare indicators) to MITRE ATT&CK.
- Correlate related indicators and reduce duplicate alerts.
- Prioritise vulnerabilities using context.
- Provide SOC dashboard, investigation, alert and executive views.
- Deliver awareness modules, a quiz, an awareness score and learning recommendations.
- Apply secure-development practices and automated testing.

## 4. Cybersecurity Awareness
Awareness reduces human-layer risk: recognising phishing, using unique passwords with a password manager, enabling (preferably phishing-resistant) MFA, resisting social engineering, browsing and connecting safely, updating software, protecting data and reporting quickly. The platform implements 15 modules, each covering *what it is, why it matters, warning signs, safe practices, and what to do if something happens*.

## 5. Cyber Threat Intelligence
CTI follows a lifecycle: direction, collection, processing, analysis, dissemination and feedback. This project implements collection (CSV feed), processing (normalisation, validation), analysis (scoring, correlation, ATT&CK) and dissemination (dashboard, alerts, executive summary), and feeds analyst decisions back through status changes and notes.

## 6. Threat Intelligence Types
Strategic (executive trends), tactical (TTPs), operational (specific campaigns) and technical (concrete IOCs). The project focuses on **technical + tactical + awareness-oriented** intelligence, with a light strategic view on the executive page.

## 7. IOC and IOA Concepts
An **IOC** is an artifact (IP, domain, URL, hash, sender) suggesting compromise; an **IOA** is a behavioural pattern indicating an attack in progress. IOCs are easy for adversaries to change and prone to staleness and shared infrastructure, so **IOC match ≠ confirmed compromise**. The platform encodes this through an *evidence ladder* (Observation → Indicator → Alert → Threat → Incident) and never auto-declares incidents.

## 8. Threat Intelligence Lifecycle (IOC lifecycle in the system)
Observed → Validated → Enriched → Scored → Investigated → Monitored → Expired/Closed, recorded as timeline events for every record.

## 9. Proposed System
A single Flask application serving a REST API and static frontend, backed by SQLite. Business logic is isolated in service modules (validator, enrichment, risk, correlation, alerts, ATT&CK, vulnerabilities, awareness, executive) that are unit-tested independently of HTTP.

## 10. Architecture
Synthetic data → ingestion → normalisation → IOC validation/extraction → enrichment → risk & confidence engine → correlation engine → {threat DB, alert engine, ATT&CK mapping} → SOC dashboard → analyst; in parallel, awareness content → modules → quiz engine → awareness score → recommendations. See `docs/02_ARCHITECTURE.md`.

## 11. Synthetic Dataset
`data/generate_threat_data.py` produces 2,004 records (seeded, reproducible) across 10 categories and 6 indicator types, with sources, reliability grades, first/last seen, observation counts, campaigns (~55% of records), optional region, behaviour, ATT&CK fields and CVE references. **Safety:** IPs come only from RFC 5737/3849 documentation ranges; domains from RFC 2606/6761 reserved names (`example.*`, `.invalid`); hashes are random 256-bit values; CVEs use the fake year 2099. Every row is labelled *SYNTHETIC / DEMO ONLY*, and a test asserts these properties. Four hand-specified records form the demo scenario (THR-2026-001…004) and one record simulates a 100-sighting scanning burst.

## 12. IOC Validation
`validate_indicator()` checks syntax only for IPv4/IPv6 (`ipaddress`), domains (label rules, IDNA, TLD), URLs (scheme, host), MD5/SHA-1/SHA-256-format hashes, email senders and CVE IDs. It accepts defanged input (`hxxp`, `[.]`), returns `valid, indicator_type, normalized_value, validation_notes`, and states explicitly that validity is not maliciousness.

## 13. Threat Enrichment
`enrich_indicator()` uses only local data: first/last seen, categories, severity, risk, confidence, sources, campaigns, related indicators, related alerts, ATT&CK mappings, analyst notes, plus offline facts (e.g., documentation range, spoofable sender). A test disables sockets to prove no network access occurs.

## 14. Risk Scoring
Weighted 0–100 score: severity 30%, confidence 25%, recency 15%, observation frequency 10% (log-scaled), source reliability 10%, context/correlation 10%, classified into INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL. Each record stores its component breakdown for explainability. Demo: 24 + 21.25 + 15 + 5.2 + 7.5 + 5 = 77.95 → **78 (HIGH)**.

## 15. Confidence Scoring
Base from source grade (A 45, B 35, C 25, D 10) + corroborating sources (+10 each, max 30) + validation (+5) + behavioural context (+10) + analyst review (+5) − staleness penalty; malformed data capped at 20. Demo: 35 + 30 + 5 + 10 + 5 = **85**.

## 16. Source Reliability
Grades A–D (Highly Reliable → Reliability Unknown) for Internal SOC, Security Vendor, Research Report, Public Threat Feed, Community Submission and Unknown Source. Reliability describes the *source*; confidence describes the *item*.

## 17. Threat Correlation
Union-find clustering links records sharing a campaign (within an observation window) or an indicator value. 123 clusters were found in the dataset. Correlated counts feed risk context; clusters of ≥ 3 generate one cluster alert. Correlation is not attribution.

## 18. MITRE ATT&CK
Behaviour-based mapping to 24 Enterprise techniques (e.g., T1566.002, T1598.003, T1190, T1071.001, T1486, T1621). 1,446 records (72%) are mapped; 558 feed-only records are intentionally unmapped. Each mapping records its justification.

## 19. Vulnerability Awareness
62 synthetic vulnerabilities with CVSS, patch status, demo exploitation status, asset criticality and exposure. Priority = CVSS 35% + asset 25% + exposure 20% + exploitation 20% (+5 sensitive data), banded P1–P4. The CVSS 9.8 isolated asset scores 44.5 (P3) while the CVSS 8.1 internet-facing, exploited VPN scores 98.3 (P1).

## 20. Alert Management
Rules: critical risk, high risk with high confidence, high risk with low confidence ("validate first"), repeated observations, correlated clusters and high-priority vulnerabilities. `correlate_alerts()` merges duplicates within a time window; 570 raw candidates became 470 alerts, and 100 burst sightings became one alert with observation count 100. Statuses: NEW, INVESTIGATING, MONITORING, RESOLVED, FALSE_POSITIVE.

## 21. SOC Workflow
Feed → detection → validation → enrichment → scoring → alert → queue → triage → correlation → investigation → escalate/monitor/resolve/false positive → documentation, supported by the alert queue, investigation view, analyst notes, status updates and audit log.

## 22. Awareness Center
15 modules including Phishing (with an annotated, clearly fictional example), Password Security, MFA (passkeys/WebAuthn), Social Engineering, Safe Browsing, Secure Wi-Fi, Software Updates, Ransomware, USB safety, Data Privacy, Mobile, Remote Work, Cloud Accounts, Incident Reporting and AI-enabled scams, plus an incident-response lifecycle and checklist.

## 23. Quiz System
40 questions (4 per category across 10 categories) with explanations. Answers are never sent to the browser before submission. Scoring yields an overall 0–100 score and band (Needs Improvement / Basic / Good / Strong), category scores, weakest areas, and recommendations (<50% Complete, 50–79% Review, ≥80% none). Results are stored anonymously, and the score is explicitly *not* an employee competency judgement.

## 24. Executive Dashboard
Plain-language headline, active critical/high counts, open alerts, P1 vulnerabilities, confirmed incidents (0), top threat and vulnerability categories, the awareness trend (59.3 → 70.8 in the synthetic history), top weaknesses and recommended priorities.

## 25. Testing
40 pytest tests (unit + integration) using a fresh temporary database per test: validation (11), scoring and reliability, enrichment, network-free search, correlation, duplicates, alert generation and correlation, status updates, notes, ATT&CK, vulnerability priority, dashboard stats, filtering, sorting, modules, quiz scoring, recommendations, empty dataset, API validation, persistence, XSS sanitisation, RBAC, security headers, defanging and dataset safety. **Result: 40/40 passed.** All nine pages were also checked manually in a browser.

## 26. Security
API-key RBAC (viewer/analyst/admin) with constant-time comparison; audit log; server-side sanitisation and client-side `textContent` rendering; strict Content-Security-Policy; enum whitelists and parameterised SQL; request size limit; rate limiting; secrets in `.env`; generic error messages; localhost binding; no outbound network code. Threat intel itself is access-controlled because it reveals defensive knowledge and may carry sharing restrictions.

## 27. Results
| Metric | Value |
|---|---|
| Threat records ingested / rejected | 2,004 / 0 |
| Severity mix | 14 critical · 492 high · 1,277 medium · 219 low · 2 informational |
| Indicator types | 674 IP · 467 domain · 349 URL · 217 hash · 158 CVE · 139 email |
| ATT&CK-mapped records | 1,446 (72%) across 24 techniques |
| Correlated clusters | 123 |
| Alerts | 570 candidates → 470 after correlation (−17.5%) |
| Vulnerabilities | 62 (2 P1, 28 P2, 26 P3, 6 P4) |
| Awareness modules / quiz questions | 15 / 40 |
| Automated tests | 40 passed |

## 28. Limitations
Synthetic data cannot reproduce real-world noise and adversary adaptation; the weights are expert-chosen, not learned; enrichment is local-only; ATT&CK mappings are rule-based per behaviour; the rate limiter is in-memory (single process); API keys are a simple auth model compared with SSO; SQLite is not designed for high concurrency; Chart.js is loaded from a CDN (tables are shown if offline).

## 29. Future Scope
Authorised live feeds, STIX/TAXII, SIEM/SOAR integration, NVD/CISA KEV/EPSS-based vulnerability data, IOC expiry, learned confidence, graph clustering, ATT&CK Navigator export, EDR/email telemetry, SSO and role dashboards, Docker, CI/CD and centralised logging (see `docs/11_FUTURE_IMPROVEMENTS.md`).

## 30. Conclusion
The project shows that useful threat intelligence is not a list of "bad" indicators but a disciplined process: validate, add context, score risk and confidence separately, map behaviour carefully, correlate without over-claiming, and keep the analyst in control. Pairing this with targeted awareness closes the loop between what the SOC sees and what people learn. All of it is achieved defensively, with synthetic data, and without ever touching a suspicious system.

---
*This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.*
