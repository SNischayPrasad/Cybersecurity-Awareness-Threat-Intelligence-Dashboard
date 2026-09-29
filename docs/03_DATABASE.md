# 03 · Database Design (SQLite)

Schema file: [`backend/models/schema.sql`](../backend/models/schema.sql). Rebuild at any time with `python -m backend.init_db`.

## Entity-relationship overview

```
sources 1───* threats 1───* indicators
                  │  1───* attack_mappings
                  │  1───* analyst_notes
                  │  1───* threat_timeline
                  │  1───* alerts (threat_id nullable: vulnerability alerts have none)
                  └── cve_id ···> vulnerabilities.cve_id   (logical link)

awareness_modules      quiz_results (anonymous)      audit_log      app_meta
```

## Tables

| Table | Key columns | Purpose |
|---|---|---|
| **THREATS** | `threat_id` PK, threat_name, category, description, severity, impact_level, risk_score, confidence_score, status, first_seen, last_seen, observation_count, campaign_id, region, behavior_observed, cve_id, source_id FK, risk_breakdown_json | One intelligence record (indicator + context). CHECK constraints enforce valid severities, statuses and 0–100 scores. |
| **INDICATORS** | `indicator_id` PK, threat_id FK, indicator_type, indicator_value, normalized_value, is_primary, first_seen, last_seen | IOCs. One primary per threat plus related ones (e.g., the demo IP on the demo domain record). |
| **SOURCES** | `source_id` PK, source_name UNIQUE, source_type, reliability (A–D) | Intelligence sources and their grade. |
| **ATTACK_MAPPINGS** | `mapping_id` PK, threat_id FK, tactic, technique, technique_id_optional, mapping_basis | Created only when behaviour justifies it; `mapping_basis` records why. |
| **VULNERABILITIES** | `vulnerability_id` PK, cve_id UNIQUE, product_category, severity, cvss_score, patch_available, exploitation_status_demo, asset_criticality, exposure, priority_score, priority_band | Synthetic CVE-2099-* register with contextual priority. |
| **ALERTS** | `alert_id` PK, threat_id FK (nullable), vulnerability_cve, indicator_value, alert_type, severity, risk_score, confidence_score, description, status, observation_count, related_threat_ids, first_observed, last_observed, created_at | Correlated alerts. `observation_count` shows how many raw signals were merged. |
| **ANALYST_NOTES** | `note_id` PK, threat_id FK, author, note, created_at | Investigation documentation (sanitised text). |
| **THREAT_TIMELINE** | `event_id` PK, threat_id FK, event_time, event_type, detail | FIRST_SEEN → NEW_OBSERVATIONS → RISK_INCREASED/DECREASED → INVESTIGATION_STARTED → MONITORING → CLOSED. |
| **AWARENESS_MODULES** | `module_id` PK, title, category, content_json | 15 modules loaded from `awareness/modules.json`. |
| **QUIZ_RESULTS** | `result_id` PK, anonymous_user_id_optional, overall_score, band, category_scores_json, is_synthetic, created_at | Anonymous quiz results; synthetic history is flagged. |
| **AUDIT_LOG** | `audit_id` PK, actor_role, action, target, detail, created_at | Every write through the API (create/update/notes/status). |
| **APP_META** | key PK, value | Pipeline stats (dataset reference date, alert de-duplication counts). |

## Relationships

- `threats.source_id → sources.source_id` (many threats per source).
- `indicators`, `attack_mappings`, `analyst_notes` and `threat_timeline` use `threat_id → threats.threat_id ON DELETE CASCADE`: child rows never outlive their threat.
- `alerts.threat_id → threats.threat_id ON DELETE SET NULL`: alert history survives if a threat record is removed.
- `threats.cve_id` logically references `vulnerabilities.cve_id` (not enforced, because a feed may mention a CVE before it is in our register).

## Indexes (and why)

| Index | Speeds up |
|---|---|
| `threats(category)`, `(severity)`, `(status)` | Dashboard filters and GROUP BY charts |
| `threats(last_seen)`, `(risk_score)` | "Newest" and "Highest risk" sorting |
| `threats(campaign_id)` | Correlation and related-threat lookups |
| `indicators(normalized_value)` | **IOC search**: exact-match lookup in O(log n) |
| `indicators(threat_id)`, `(indicator_type)` | Joins and IOC-type distribution |
| `attack_mappings(threat_id)`, `(technique_id_optional)` | ATT&CK drill-down (technique → records) |
| `alerts(status)`, `(threat_id)` | Alert queue and related alerts |
| `analyst_notes(threat_id)`, `threat_timeline(threat_id)` | Investigation view |

## Design decisions

- **Normalised values**: indicators are stored lower-cased/compressed (`normalized_value`) so `LOGIN-CHECK.INVALID` and `login-check.invalid` match.
- **Scores are stored AND explained**: `risk_breakdown_json` keeps every weighted component so the UI can show *why* a score is 78.
- **Parameterised SQL everywhere**: user input never gets concatenated into SQL. Sort columns come from a whitelist (`SORT_OPTIONS`).
- **Anonymous quiz results**: no names or emails are stored (data minimisation).
