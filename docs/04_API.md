# 04 · REST API Reference

Base URL: `http://127.0.0.1:5000`. All responses are JSON.

## Authentication & authorization (RBAC)

| Role | How | Can do |
|---|---|---|
| **viewer** | no header | All `GET` endpoints, quiz submission, priority calculator |
| **analyst** | `X-API-Key: <ANALYST_API_KEY>` | + add analyst notes, change threat status / observations, change alert status |
| **admin** | `X-API-Key: <ADMIN_API_KEY>` | + create threats, edit threat name/description |

Keys come from `.env` (see `.env.example`) and are compared in constant time (`hmac.compare_digest`). In `APP_ENV=production` the server refuses to start without keys.

## Common error format

```json
{ "error": "validation_error", "message": "Threat record failed validation.", "details": ["indicator_value is not valid: ..."] }
```

| Status | Meaning |
|---|---|
| 200 / 201 | OK / created |
| 400 | Malformed request (missing body, non-JSON, bad query parameter type) |
| 401 | No/invalid API key for a protected action |
| 403 | Valid key, but role is not allowed |
| 404 | Resource not found |
| 422 | Well-formed but fails validation (bad indicator, unknown category, invalid status) |
| 429 | Rate limit exceeded (`RATE_LIMIT_PER_MINUTE` per client IP) |
| 500 | Unexpected error (generic message; details only in server log) |

---

## Endpoints

### `GET /api/threats`
- **Request (query):** `severity` (comma list), `category`, `indicator_type`, `status`, `min_risk`, `max_risk`, `min_confidence`, `max_confidence`, `date_from`, `date_to` (last_seen, YYYY-MM-DD), `q` (text), `campaign_id`, `technique_id`, `tactic`, `sort` = `newest|oldest|risk|confidence|observed`, `page`, `page_size` (1–100).
- **Response:** `{ items: [...], total, page, page_size, pages }`. Each item includes `indicator_defanged`.
- **Validation:** integer parameters checked (400 otherwise); sort is whitelisted; all values bound as SQL parameters.
- **Auth:** none (viewer).
- **Example:** `GET /api/threats?severity=HIGH,CRITICAL&category=PHISHING&sort=risk`

### `GET /api/threats/{id}`
- **Response:** full investigation object: record, `risk_breakdown`, `source` (reliability), `indicators`, `attack_mappings` (+ reference URL, never fetched), `attack_mapping_note`, `related_threats`, `related_alerts`, `analyst_notes`, `timeline`, `vulnerability`, `interpretation`, `recommended_actions`, `category_info`, `evidence_level`.
- **Status:** 200, 404.

### `POST /api/threats`  (admin)
- **Request body:**
```json
{ "threat_name": "Synthetic Test Phishing Domain", "threat_category": "PHISHING",
  "indicator_type": "DOMAIN", "indicator_value": "test-lure.invalid", "severity": "HIGH",
  "source_name": "Internal SOC", "behavior_observed": "email_link_lure",
  "corroborating_sources": 2, "analyst_verified": false, "description": "..." }
```
- **Processing:** normalise → validate indicator syntax → sanitise text → compute confidence (unless `confidence_score` supplied) → compute risk with correlation context → ATT&CK map if behaviour justifies → store → generate alerts → audit.
- **Response:** 201 + the new threat detail (ID auto-assigned `THR-YYYY-NNN`).
- **Status:** 201, 400 (not JSON), 401, 403 (analyst), 422 (validation).

### `PUT /api/threats/{id}`  (analyst; name/description need admin)
- **Body (any of):** `status`, `observation_count` (can only increase), `last_seen`, `threat_name`*, `description`* (*admin).
- **Effects:** timeline events (status change, NEW_OBSERVATIONS, RISK_INCREASED/DECREASED), automatic re-scoring when evidence changes, audit entry.
- **Status:** 200, 400, 401, 403, 404, 422 (unknown field such as `risk_score`: scores can't be set by hand).

### `POST /api/threats/{id}/notes`  (analyst)
- **Body:** `{ "note": "Checked proxy logs, no hits", "author": "tier1-analyst" }`
- **Validation:** HTML tags/control chars stripped, 3–2000 chars.
- **Status:** 201, 400, 401, 404, 422.

### `GET /api/indicators/search?q=...`
- **Request:** `q`: any IP / domain / URL / hash / email / CVE (defanged input like `hxxp://x[.]invalid` accepted).
- **Response:** `validation`, `known_in_dataset`, `indicator_type`, `risk_score`, `severity`, `confidence_score`, `associated_category_labels`, `first_seen`, `last_seen`, `status`, `related_indicators`, `related_alerts`, `attack_mappings`, `analyst_notes`, `local_context`, `interpretation`, `caution`, and `"network_activity": "NONE - database lookup only..."`.
- **Security:** database lookup only. The value is never resolved, fetched or pinged.
- **Status:** 200, 400 (missing/too long).

### `GET /api/indicators/validate?value=...&type=...`
Syntax validation only → `{ valid, indicator_type, subtype, normalized_value, validation_notes }`.

### `GET /api/dashboard/stats`
KPI cards, evidence ladder, severity/category/IOC-type/status counts, risk & confidence histograms, vulnerabilities by severity, top categories by risk, top tactics.

### `GET /api/dashboard/trends?weeks=26`
Weekly counts (pandas resample) → `{ labels, total, high_or_critical }`. 400 if `weeks` isn't an integer.

### `GET /api/alerts`
- **Query:** `status` (comma list), `severity`, `alert_type`, `limit` (≤1000).
- **Response:** `{ items, count }`, ordered open-first then by severity.

### `GET /api/alerts/summary`
Counts by status/type/severity + `raw_candidates` vs `after_correlation` (alert-fatigue metric).

### `PUT /api/alerts/{id}/status`  (analyst)
- **Body:** `{ "status": "INVESTIGATING", "comment": "optional" }`. Allowed: NEW, INVESTIGATING, MONITORING, RESOLVED, FALSE_POSITIVE.
- **Status:** 200, 400, 401, 404, 422. Audited.

### `GET /api/vulnerabilities`
- **Query:** `severity`, `band` (P1–P4), `sort` = `priority|cvss|published`.
- **Response:** `{ items, count, stats, note }`.

### `POST /api/vulnerabilities/prioritize`
- **Body:** `{ "cvss_score": 8.1, "asset_criticality": "CRITICAL", "exposure": "INTERNET_FACING", "exploitation_status": "EXPLOITATION_REPORTED_DEMO", "handles_sensitive_data": true, "patch_available": true }`
- **Response:** `{ priority_score, priority_band, recommended_timeline, rationale[] }`. Pure calculation, nothing stored.
- **Status:** 200, 400, 422 (CVSS outside 0–10, unknown enum).

### `GET /api/awareness/modules` · `GET /api/awareness/modules/{id}`
15 modules with `what_is_it`, `why_it_matters`, `warning_signs`, `safe_practices`, `what_to_do`, `extra_sections`. 404 for an unknown id.

### `GET /api/quiz?shuffle=true|false`
Questions **without answers or explanations** (answers never reach the browser before submission).

### `POST /api/quiz/submit`
- **Body:** `{ "answers": { "Q01": "C", "Q02": "B" }, "anonymous_user_id": "optional-anon-id" }`
- **Response (201):** `overall_score`, `band`, `category_scores`, `weakest_areas`, `recommendations`, per-question `feedback` with explanations, `disclaimer`.
- **Validation:** answers must be a non-empty object with known question IDs; anonymous id `[A-Za-z0-9-]{1,40}`.

### Supporting endpoints
| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Status, record count, dataset reference date |
| `GET /api/auth/whoami` | Role for the supplied key (viewer/analyst/admin) |
| `GET /api/attack/summary` | Tactics, techniques, matrix, mapped vs unmapped counts |
| `GET /api/correlation/clusters?min_size=2&limit=50` | Related threat clusters (+ "not attribution" note) |
| `GET /api/executive/summary` | Plain-language management summary |
| `GET /api/categories` | Threat category knowledge base |
| `GET /api/sources` | Source reliability reference |

## Try it (PowerShell)

```powershell
Invoke-RestMethod "http://127.0.0.1:5000/api/indicators/search?q=198.51.100.25"
Invoke-RestMethod -Method Put -Uri "http://127.0.0.1:5000/api/alerts/ALR-00001/status" `
  -Headers @{ "X-API-Key" = "change-me-analyst-key" } -ContentType "application/json" `
  -Body '{"status":"INVESTIGATING"}'
```

## Try it (curl, macOS/Linux/Git Bash)

```bash
curl "http://127.0.0.1:5000/api/threats?severity=CRITICAL&sort=risk&page_size=5"
curl -X POST http://127.0.0.1:5000/api/quiz/submit -H "Content-Type: application/json" -d '{"answers":{"Q01":"C"}}'
```
