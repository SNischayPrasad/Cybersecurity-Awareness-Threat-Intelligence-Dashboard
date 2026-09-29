# 11 · Future Improvements (all defensive)

| Area | Improvement | Notes |
|---|---|---|
| Live intelligence | **Authorised live threat-feed integration** | Pull from feeds you have permission to use, via API keys in `.env`; store raw + normalised; keep offline mode. |
| Standards | **STIX 2.1 / TAXII 2.1** | Represent indicators, relationships and sightings as STIX objects; subscribe to TAXII collections. |
| SIEM | **SIEM integration** | Export high-confidence IOCs as watchlists; import sightings (matches in logs) as observations. |
| SOAR | **SOAR playbooks** | Automate enrichment and ticket creation. Keep containment actions *human-approved*. |
| Vulnerabilities | **CVE feed integration (NVD)** | Replace synthetic CVE-2099 records with authorised public data for awareness. |
| Vulnerabilities | **CISA KEV awareness** | Flag vulnerabilities on the Known Exploited Vulnerabilities catalogue as P1 candidates. |
| Vulnerabilities | **EPSS-style prioritisation** | Add exploit-probability as a factor alongside CVSS and context. |
| Data quality | **Threat-feed de-duplication** | Merge the same IOC from multiple feeds into one record with multiple sightings/sources. |
| Data quality | **IOC expiration / TTLs** | Auto-expire indicators by type (IPs fast, hashes slow) unless re-observed. |
| Scoring | **Better confidence scoring** | Track per-source historical precision (true vs false positives) and learn weights. |
| Automation | **Automated enrichment** | Passive DNS / WHOIS age / sandbox verdicts *from authorised providers only*, still never touching the indicator directly. |
| Analytics | **Threat clustering** | Graph-based clustering (shared infrastructure, time, TTPs) with visual link analysis. |
| ATT&CK | **ATT&CK Navigator export** | Export a layer JSON to heat-map observed techniques and detection coverage. |
| Telemetry | **Email-security integration** | Correlate phishing IOCs with reported messages and user-report rates. |
| Telemetry | **Endpoint telemetry integration** | Hash sightings from EDR to confirm (or rule out) real impact. |
| Cloud | **Cloud-security intelligence** | Cloud audit logs, misconfiguration findings, identity anomalies. |
| Hunting | **Threat hunting workspace** | Save hypotheses, queries and outcomes linked to ATT&CK techniques. |
| Reporting | **Advanced executive reporting** | PDF export, trends vs. targets, risk appetite thresholds. |
| Access | **Role-based dashboards + SSO** | OIDC/SAML login, per-role views, notes readable only by analysts. |
| Ops | **Docker deployment** | `Dockerfile` + `docker-compose` (app + PostgreSQL + reverse proxy with TLS). |
| Ops | **CI/CD** | GitHub Actions: run `pytest`, linting (ruff), dependency and secret scanning on every push. |
| Ops | **Centralised logging** | Structured JSON logs shipped to a log platform; alert on API abuse (429s, 401 spikes). |
| Stack | **Option B/C migration** | FastAPI + PostgreSQL + React/Recharts; Redis for rate limits/caching. |
| Awareness | **Adaptive learning** | Question banks per module, spaced repetition, phishing-report training (never real phishing kits). |
