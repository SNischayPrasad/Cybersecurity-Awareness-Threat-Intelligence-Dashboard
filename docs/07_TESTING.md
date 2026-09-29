# 07 · Testing Strategy

**Tooling:** `pytest` (40 automated tests) + Flask's test client. Run with:

```powershell
python -m pytest -v
```

**Isolation:** each test builds a *fresh temporary SQLite database* from a small generated dataset (200 records + the 4 demo records, 20 vulnerabilities). Tests never touch `data/threat_intel.db` and never need the internet. Test 17 goes further: it replaces the socket functions with ones that fail, proving the IOC search makes **no network connection**.

**Levels covered**
- *Unit*: validator, scoring, correlation, alert rules, ATT&CK mapping, vulnerability priority, recommendations, sanitiser, generator safety.
- *Integration*: REST endpoints + database (create, update, notes, filters, sorting, quiz, RBAC, headers).
- *Edge cases*: empty dataset, malformed JSON, invalid enums, unknown IDs, wrong/missing API keys, stale data.
- *Manual/UI*: all 9 pages checked in a browser (charts render, no console errors, search, drill-downs, quiz submission).

## Test case table

Last run: **40 passed, 0 failed** (Python 3.13, pytest 9).

| ID | Scenario | Input | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | Valid IPv4 | `198.51.100.25` | valid, IP/IPv4, documentation-range note | As expected | ✅ Pass |
| 2 | Invalid IPv4 | `256.10.10.10`, `198.51.100`, `1.2.3.4.5` | invalid | As expected | ✅ Pass |
| 3 | Valid IPv6 | `2001:DB8:0:0::1` | valid, normalised `2001:db8::1` | As expected | ✅ Pass |
| 4 | Valid domain | `Login-Check.INVALID.` | valid, normalised `login-check.invalid`, reserved note | As expected | ✅ Pass |
| 5 | Invalid domain | `-bad-.invalid`, `nodot`, `a..example.com`… | invalid | As expected | ✅ Pass |
| 6 | Valid URL | `hxxps://login-check[.]invalid/verify/session` | valid, refanged + normalised, "NOT visited"; `javascript:` rejected | As expected | ✅ Pass |
| 7 | Valid MD5-format hash | 32 hex chars | valid, subtype MD5 | As expected | ✅ Pass |
| 8 | Valid SHA-1-format hash | 40 hex chars (upper-case) | valid, SHA1, lower-cased | As expected | ✅ Pass |
| 9 | Valid SHA-256-format hash | 64 hex chars | valid; non-hex / wrong length invalid | As expected | ✅ Pass |
| 10 | Valid CVE format | `cve-2099-0002` | valid, `CVE-2099-0002`, synthetic note | As expected | ✅ Pass |
| 11 | Invalid CVE format | `CVE-99-1234`, `CVE-2099-12`, … | invalid | As expected | ✅ Pass |
| 12 | Threat creation | `POST /api/threats` (admin) | 201, ID assigned, scores 0–100, T1566.002 mapping, `<script>` stripped | As expected | ✅ Pass |
| 13 | Risk calculation | HIGH, conf 85, 2 days old, 5 obs, grade B, 3 correlated, mapped | 78 / HIGH; stale+weak lower; bad severity raises | As expected | ✅ Pass |
| 14 | Confidence calculation | B + 3 corroborations + context + analyst | 85; unvalidated ≤ 20; staleness lowers; interpretations | As expected | ✅ Pass |
| 15 | Source reliability | Internal SOC / Security Vendor / unknown | A / "Usually Reliable" / D | As expected | ✅ Pass |
| 16 | IOC enrichment | `198.51.100.25` | known, risk 78, conf 85, MONITORING, related `login-check.invalid`, notes; unknown IP → "not evidence of safety" | As expected | ✅ Pass |
| 17 | Indicator search | domain / defanged URL / IP with sockets disabled | 200, `network_activity: NONE`; missing q → 400 | As expected | ✅ Pass |
| 18 | Threat correlation | 3 records in one campaign + 1 unrelated | 1 cluster of 3 (DOMAIN, IP, FILE_HASH), "not attribution"; far-apart windows not linked | As expected | ✅ Pass |
| 19 | Duplicate observation | same IP from two records | linked by "shared indicator value" | As expected | ✅ Pass |
| 20 | Alert generation | high/high, low risk, high risk + low conf, 80 obs | HIGH_RISK / none / UNVERIFIED_HIGH_RISK / REPEATED_OBSERVATION | As expected | ✅ Pass |
| 21 | Alert correlation | 100 sightings in 5 min; 2 sightings 2.5 h apart | 1 alert with count 100; 2 alerts | As expected | ✅ Pass |
| 22 | Alert status update | PUT without key / wrong key / bad status / analyst | 401 / 401 / 422 / 200 + audit row; unknown alert 404 | As expected | ✅ Pass |
| 23 | Analyst notes | note with `<b>` tags | 201, tags stripped, shown in detail + timeline; blank → 422; no key → 401 | As expected | ✅ Pass |
| 24 | ATT&CK mapping | `email_link_lure`, `files_encrypted`, `reputation_only` | T1566.002, T1486, **None** (no guessing) | As expected | ✅ Pass |
| 25 | Vulnerability scoring | 9.8 isolated vs 8.1 internet-facing exploited | 8.1 case higher, P1 vs P3/P4; invalid inputs raise | As expected | ✅ Pass |
| 26 | Dashboard statistics | `GET /api/dashboard/stats`, `/trends` | totals consistent (204), histogram sums, incidents 0 | As expected | ✅ Pass |
| 27 | Severity filtering | `severity=HIGH,CRITICAL` | only HIGH/CRITICAL | As expected | ✅ Pass |
| 28 | Category filtering | `category=PHISHING` | only PHISHING | As expected | ✅ Pass |
| 29 | Threat sorting | sort=risk/confidence/observed/newest | each list correctly ordered | As expected | ✅ Pass |
| 30 | Awareness module retrieval | `GET /api/awareness/modules` | 15 modules, all sections present; unknown → 404 | As expected | ✅ Pass |
| 31 | Quiz scoring | all correct / all wrong | 100 "Strong Awareness" / 0 "Needs Improvement"; answers not exposed by GET | As expected | ✅ Pass |
| 32 | Learning recommendation | Phishing 40, Social Eng. 55, Passwords 90 | Complete / Review / "No immediate module required." | As expected | ✅ Pass |
| 33 | Empty dataset | header-only CSVs | stats 0, empty lists, executive summary still 200 | As expected | ✅ Pass |
| 34 | API validation | bad indicator, non-JSON, bad category, bad page, unknown id, forbidden field, CVSS 42 | 422 / 400 / 422 / 400 / 404 / 422 / 422 | As expected | ✅ Pass |
| 35 | Database persistence | create + update via API, read via new connection | status & observations persisted; timeline + audit rows | As expected | ✅ Pass |
| 36 | XSS sanitisation | `<script>…</script>Hello\x00 <b>analyst</b>` | tags/control chars removed; length capped | As expected | ✅ Pass |
| 37 | RBAC | analyst tries POST threat / rename | 403 / 403; admin whoami → admin | As expected | ✅ Pass |
| 38 | Security headers + demo scenario | `GET /api/threats/THR-…-001` | nosniff + CSP; 78/85/HIGH/MONITORING; evidence level THREAT | As expected | ✅ Pass |
| 39 | Defang display | URL, IP, hash | `hxxps://…[.]…`, `198[.]51…`, hash unchanged | As expected | ✅ Pass |
| 40 | Generator safety | 300 generated records | every IP in doc ranges, every domain reserved, CVEs 2099, all labelled synthetic | As expected | ✅ Pass |

> Keep this table honest: if a future change breaks a test, update "Actual result" and "Pass/Fail" from the real run.
