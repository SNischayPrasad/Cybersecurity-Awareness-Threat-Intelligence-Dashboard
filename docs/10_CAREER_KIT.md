# 10 · Resume, LinkedIn & Interview Preparation

> Only claim what you can explain. Read the code behind each bullet until you can walk through it on a whiteboard.

## 50. Resume / LinkedIn proof

### A. Resume bullet points
- Built a defensive **Cyber Threat Intelligence dashboard** (Python, Flask, SQLite, pandas, Chart.js) that ingests, validates, scores and correlates **2,000+ synthetic IOCs** (IP, domain, URL, hash, email, CVE) and serves them through **15+ REST endpoints** with API-key RBAC, audit logging, CSP and rate limiting.
- Designed a weighted **risk engine (severity, confidence, recency, frequency, source reliability, context)** separate from a **confidence model**, plus behaviour-based **MITRE ATT&CK mapping** (24 techniques) and union-find **threat correlation** that cut alert volume **~18% (570 → 470)** through alert de-duplication.
- Created a **security awareness platform** with 15 learning modules and a 40-question quiz producing category scores and personalised learning recommendations, alongside **contextual vulnerability prioritisation** (CVSS + asset criticality + exposure + exploitation), validated by **40 automated pytest tests**.

### B. Two-line project description
A defensive SOC-style dashboard that validates, enriches, scores, correlates and maps synthetic threat intelligence to MITRE ATT&CK, without ever contacting an indicator.
It pairs technical threat intelligence with an awareness center, quiz and executive summary, so both analysts and non-technical users can act on it.

### C. LinkedIn project description
> **Cybersecurity Awareness & Threat Intelligence Dashboard** · Python · Flask · SQLite · pandas · Chart.js
>
> I built an end-to-end defensive cybersecurity project that combines **technical threat intelligence** with **human-focused security awareness**.
>
> 🔎 **Threat intelligence pipeline**: a synthetic feed of 2,000+ safe indicators (documentation IPs, reserved domains, random hashes) flows through normalisation, IOC validation, local-only enrichment, **risk vs. confidence scoring**, source-reliability grading, behaviour-based **MITRE ATT&CK** mapping and threat correlation.
> 🚨 **SOC workflow**: alert rules with de-duplication to reduce alert fatigue, an alert queue with triage statuses, analyst notes, threat timelines and an "evidence ladder" that keeps *observation → indicator → alert → threat → incident* distinct.
> 🛡️ **Vulnerability awareness**: contextual patch prioritisation showing why a CVSS 8.1 internet-facing bug can outrank a CVSS 9.8 isolated one.
> 🎓 **Awareness Center**: 15 modules (phishing, MFA/passkeys, ransomware, AI-enabled scams…) and a 40-question quiz with category scores and personalised learning paths.
> 📊 **Executive summary** in plain language for non-technical stakeholders.
> 🔐 Built securely: API-key RBAC, audit log, CSP/XSS protection, input validation, rate limiting, and 40 automated tests, including one proving the IOC search never touches the network.
>
> Key lesson: an IOC match is a *lead*, not proof of compromise. Good threat intelligence supports analyst judgement instead of replacing it.
> #cybersecurity #threatintelligence #SOC #MITREATTACK #securityawareness #python

### D. Technical skills demonstrated
Cybersecurity fundamentals · Cyber Threat Intelligence (lifecycle, IOC/IOA, TTPs, source reliability) · SOC operations & alert triage · IOC analysis & validation (regex, `ipaddress`, IDNA, defanging) · MITRE ATT&CK mapping · Vulnerability management (CVE, CVSS, contextual prioritisation) · Risk & confidence scoring · Threat correlation (union-find clustering) · Alert de-duplication · Security awareness design · Incident-response concepts (NIST lifecycle) · Python · Flask REST APIs · SQL/SQLite schema design & indexing · pandas analytics · JavaScript & Chart.js data visualisation · Secure coding (RBAC, CSP, input validation, rate limiting, audit logging, secrets management) · pytest automated testing · Git/GitHub.

### E. GitHub repository description
Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.

---

## 52. Interview preparation: 10 questions, 10 answers

**1. Explain your project.**
> I built a Cybersecurity Awareness and Threat Intelligence Dashboard: a defensive, SOC-style web app in Flask, SQLite and JavaScript. It has two halves. The technical half ingests about 2,000 synthetic threat records, validates each indicator's syntax, scores it for risk and confidence, maps it to MITRE ATT&CK only when a behaviour was observed, correlates related indicators into clusters and generates de-duplicated alerts. Analysts can search an IOC, open an investigation view with a timeline and related indicators, add notes and change statuses. The human half is an awareness center with 15 modules and a 40-question quiz that produces category scores and learning recommendations. An executive page ties both together in plain language. A key design rule is that it never contacts an indicator: all enrichment is a local database lookup, and I wrote a test that disables network sockets to prove it. There are 40 automated tests in total.

**2. What is threat intelligence, and which types does your project cover?**
> Threat intelligence is evidence-based knowledge about threats that helps defenders make decisions. There are four types: strategic for executives, tactical about TTPs, operational about specific campaigns, and technical about concrete artifacts like IPs and hashes. My project focuses on technical intelligence (the IOCs and their scoring), tactical (ATT&CK behaviour mapping), and awareness-oriented intelligence, where I turn threat categories into training. The executive summary is a small step into strategic reporting.

**3. What is an IOC, and why doesn't an IOC match mean you were compromised?**
> An IOC is an observable artifact, such as an IP, domain, URL, file hash or sender address, that suggests malicious activity. A match isn't proof because IOCs go stale, get shared by benign infrastructure like cloud hosts or CDNs, or arrive without context. That's why my dashboard has an evidence ladder (observation, indicator, alert, threat, incident), and even the demo phishing campaign stays at "THREAT, monitoring" rather than "incident", because there's no confirmed impact.

**4. What's the difference between your risk score and confidence score?**
> Risk answers "how concerning could this be?" and confidence answers "how much do I trust this information?". Risk is a weighted score: severity 30%, confidence 25%, recency 15%, frequency 10%, source reliability 10%, and correlation context 10%. Confidence starts from the source's reliability grade, then adds corroboration, validation, behavioural context and analyst review, and subtracts for staleness. A risk-90, confidence-25 item is "potentially serious but weak evidence, so validate first". My alert engine actually creates a separate UNVERIFIED_HIGH_RISK alert type for that case instead of treating it like a confirmed high-risk hit. For the demo record I can show the math: the components add up to 77.95, which rounds to 78.

**5. How does your threat enrichment work, and what did you deliberately not do?**
> Enrichment takes a raw indicator, validates it, and pulls context from the local database: first and last seen, categories, sources with reliability grades, related indicators from the same campaign, related alerts, ATT&CK mappings and analyst notes. It also adds offline facts, for example that an IP is in a documentation range, or that an email sender can be spoofed so you should check SPF/DKIM/DMARC. What I deliberately didn't do is any DNS, WHOIS or HTTP lookup, because contacting suspicious infrastructure can tip off an adversary or expose the analyst. Live integrations would only be added through authorised APIs.

**6. How did you use MITRE ATT&CK?**
> Tactics are the adversary's goal and techniques are how they achieve it, for example Initial Access through T1566.002 Spearphishing Link. I map a record only when a behaviour was observed. If an email lure contained a link, that justifies T1566.002. If an IP was just on a reputation feed, there's no behaviour, so I leave it unmapped rather than guess. About 72% of records are mapped and 28% intentionally aren't. Each mapping stores its basis, so an analyst can see why it was applied. The ATT&CK page lets you click a technique and drill down to the records behind it.

**7. How do you prioritise vulnerabilities?**
> CVSS measures generic technical severity, but it doesn't know my environment. I combine CVSS (35%) with asset criticality (25%), exposure (20%) and exploitation evidence (20%), plus a bump for sensitive data. The demo shows a CVSS 9.8 bug on an isolated test machine scoring 44.5 (P3), while a CVSS 8.1 bug on an internet-facing VPN gateway with reported exploitation scores 98.3 (P1). That mirrors how teams use things like CISA's Known Exploited Vulnerabilities list and EPSS in practice.

**8. How does threat correlation work, and what are its limits?**
> I use union-find clustering. Two records are linked if they share a campaign ID with overlapping observation windows, or if they share the same indicator value, like one IP reported by two feeds. Clusters show the indicator types, time window, max risk and link reasons. The correlated count also feeds the risk score's context component. The limit is that correlation shows related evidence, not attribution. Shared hosting can link unrelated activity, so every cluster carries a "not attribution" note.

**9. Walk me through the SOC workflow, and how you handled alert fatigue.**
> The flow goes: feed, IOC detected, validation, enrichment, risk and confidence, alert, queue, triage, correlation, investigation, then a decision to escalate, monitor, resolve or mark false positive, and finally documentation. As a Tier 1 analyst in my dashboard, you'd filter to open critical/high alerts, check risk against confidence, open the enriched record, check related indicators and the timeline, decide, and write a note. Every change is audited. For alert fatigue, `correlate_alerts` merges candidates with the same type and indicator inside a time window. My test shows 100 sightings in five minutes becoming one alert with an observation count of 100, and across the dataset, 570 raw candidates become 470 alerts, plus one alert per correlated cluster instead of one per member.

**10. How do you handle false positives, and how did you secure the app itself?**
> On false positives: IPs are shared, domains change owners, cloud ranges host both good and bad, feeds disagree, and intel goes stale. So I score recency decay and source reliability, keep a FALSE_POSITIVE status that analysts must document, and never auto-block anything. The intel supports the analyst's decision instead of replacing it. For app security: API-key RBAC with viewer, analyst and admin roles and constant-time key comparison; an audit log for every write; input validation with enum whitelists and parameterised SQL; HTML stripping on the server plus `textContent` rendering and a strict Content Security Policy against XSS; rate limiting; secrets in `.env`; and generic error messages. Threat intel itself needs access control, because your IOC list and notes reveal what you know and how you're exposed.
