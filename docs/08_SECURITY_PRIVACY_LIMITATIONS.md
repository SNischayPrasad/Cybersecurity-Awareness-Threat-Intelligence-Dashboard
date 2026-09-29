# 08 · Security, Privacy, False Positives & Intelligence Limitations

## 44. Security & privacy controls

| Principle | How this project implements it |
|---|---|
| **Never automatically visit suspicious URLs** | No HTTP client code exists in the backend. URLs are parsed as text (`urllib.parse`) only. The UI shows them defanged (`hxxps://…[.]…`) so they are not clickable. |
| **Never execute files based on hashes** | Hashes are validated as strings; there is no download or execute path. |
| **Never contact suspicious IPs/domains** | No DNS, WHOIS, ping or socket calls. Test 17 disables sockets and proves search still works. |
| **Sanitise threat descriptions** | `sanitize_text()` strips HTML tags and control characters and caps length before storage. |
| **Prevent XSS** | Frontend builds DOM with `textContent` (never `innerHTML`); strict **Content-Security-Policy** allows scripts only from self + the Chart.js CDN and blocks inline scripts. |
| **Validate API input** | Enum whitelists (category, status, severity, type), IOC syntax validation, integer checks, max body size 64 KB, sort-column whitelist, parameterised SQL. |
| **Authenticate analyst functions** | `X-API-Key` header; constant-time comparison; 401 for missing/invalid keys. |
| **RBAC** | viewer → analyst → admin (`require_role`). Analysts cannot create threats; only admins edit names/descriptions. 403 on insufficient role. |
| **Protect analyst notes** | Writing requires the analyst role; every note is audited. (Production: also restrict *reading* notes, see below.) |
| **Rate-limit APIs** | Sliding-window limiter per client IP (`RATE_LIMIT_PER_MINUTE`), 429 when exceeded. |
| **Protect API keys / use env vars** | Keys live in `.env` (git-ignored); `.env.example` has placeholders; production refuses to start without keys. |
| **Use HTTPS** | Dev server binds to `127.0.0.1` only. For deployment, put it behind a TLS reverse proxy (nginx/Caddy) and a production WSGI server (gunicorn/waitress). |
| **Audit administrative changes** | `audit_log` records role, action, target, detail and time for every write. |
| **Minimise personal data** | No user accounts, names or emails. Quiz results are anonymous. Threat data is synthetic. |
| **Safe errors** | Unhandled exceptions return a generic 500 message; stack traces stay in server logs. Debug mode is off. |
| **Other headers** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`. |

### Why threat-intelligence data itself needs access control
- **It reveals what you know.** An attacker who reads your IOC list learns which infrastructure is "burned" and which isn't detected yet.
- **Analyst notes may contain sensitive details**: internal hostnames, usernames, incident scope, weaknesses.
- **Sharing agreements** (e.g., Traffic Light Protocol, TLP:RED/AMBER) legally/ethically restrict redistribution of some intel.
- **Integrity matters**: if anyone can edit intel, an attacker could mark their own infrastructure as a false positive. Hence RBAC + audit logging.

## 45. False positives & intelligence limitations

- **An IP may be shared by many users**: cloud hosting, CDNs, VPN exits, mobile carrier NAT. Blocking it may block legitimate services.
- **A domain may change ownership**: an expired malicious domain can be re-registered by someone benign (or a sinkhole).
- **Cloud infrastructure hosts both benign and malicious services** on the same address ranges.
- **Indicators become stale**: attackers rotate infrastructure quickly; recency scoring decays old items.
- **Threat feeds can disagree**: one says malicious, another says benign. Hence source reliability + corroboration in confidence.
- **Confidence varies**: a single unverified community submission ≠ confirmed internal sighting.
- **Correlation does not prove attribution**: shared infrastructure can be coincidence or shared hosting.
- **Absence of intelligence is not evidence of safety**: "not found in dataset" never means "safe".

> **Therefore: threat intelligence should *support* analyst decisions rather than automatically be treated as unquestionable truth.** This is why the dashboard shows evidence levels, separates risk from confidence, records the reasoning (`mapping_basis`, risk breakdown), and leaves final decisions to analysts.

## Ethical scope
This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems. All indicators are synthetic: RFC 5737/3849 documentation IP ranges, RFC 2606/6761 reserved domains, random hash-format strings and fake `CVE-2099-*` IDs.
