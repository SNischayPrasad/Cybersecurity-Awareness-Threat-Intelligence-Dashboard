# 05 · Correlation, Timeline, Alerts, SOC Workflow & Incident Response

## 18. Threat correlation (`correlate_threats`)

Union-find clustering links two records when **either**:
1. they share a `campaign_id` **and** their observation windows are within `window_days` (default 60), or
2. they share the same normalised indicator value (e.g., two feeds reporting the same IP).

Example cluster:

| Indicator | Type | Link |
|---|---|---|
| `login-check.invalid` | DOMAIN | campaign CMP-DEMO-001 |
| `198.51.100.25` | IP | campaign CMP-DEMO-001 |
| `hxxps://login-check[.]invalid/verify/session` | URL | campaign CMP-DEMO-001 |
| `security-alert@login-check[.]invalid` | EMAIL | campaign CMP-DEMO-001 |

→ **RELATED THREAT CLUSTER**, with `link_reasons`, `strength` (MODERATE or STRONG when several link types agree), `max_risk`, `avg_confidence`.

> **Correlation indicates a relationship in the evidence, not guaranteed attribution.** Two indicators in a cluster tell us they were seen together, not *who* is behind them.

The number of correlated records also feeds the **context** component of the risk score.

## 19. Threat timeline

Every record gets lifecycle events in `threat_timeline`:

```
FIRST_SEEN → NEW_OBSERVATIONS → RISK_ASSESSED / RISK_INCREASED / RISK_DECREASED
          → INVESTIGATION_STARTED → MONITORING → CLOSED (or FALSE_POSITIVE)
```

Updates made through the API add events automatically (status change, new observations, re-scoring, analyst notes). The investigation view draws this as a vertical timeline.

## 31. Alert engine (`generate_threat_alert` and friends)

| Rule | Alert type | Severity |
|---|---|---|
| risk ≥ 81 and confidence ≥ 50 | `CRITICAL_RISK_INDICATOR` | CRITICAL |
| risk ≥ 61 and confidence ≥ 60 | `HIGH_RISK_INDICATOR` | HIGH |
| risk ≥ 61 but confidence < 40 | `UNVERIFIED_HIGH_RISK` ("validate first") | MEDIUM |
| observation_count ≥ 50 | `REPEATED_OBSERVATION` | ≥ MEDIUM |
| correlated cluster of ≥ 3 with an active member and max risk ≥ 61 | `CORRELATED_INDICATORS` (one per cluster) | HIGH / CRITICAL |
| vulnerability priority ≥ 80 | `HIGH_PRIORITY_VULNERABILITY` | HIGH / CRITICAL |

Thresholds are configurable in `.env`. Alert fields: `alert_id, threat_id, timestamp (created_at), alert_type, severity, risk_score, confidence_score, description, status, observation_count, related_threat_ids`. Statuses: NEW, INVESTIGATING, MONITORING, RESOLVED, FALSE_POSITIVE.

## 32. Alert correlation (`correlate_alerts`) and alert fatigue

**Alert fatigue**: when analysts see hundreds of near-identical alerts, they start skimming, and the one real attack gets missed. Tools that "cry wolf" lose trust.

`correlate_alerts()` merges candidates with the same `(alert_type, indicator)` inside a time window:

```
100 × "Sensor sighting of 203.0.113.77" within 5 minutes
        ↓ correlate_alerts(window_minutes=5)
1 alert · observation_count = 100 · first_observed / last_observed
```

In the demo database: **570 raw alert candidates → 470 alerts** after correlation (and one cluster alert replaces what would otherwise be one alert per campaign member). The Alerts page shows these numbers live.

## 33. SOC investigation workflow

```
Threat Feed → IOC Detected → Validation → Enrichment → Risk + Confidence → Alert → SOC Queue
   → Analyst Triage → Correlation → Investigation
   → Escalate / Monitor / Resolve / False Positive → Documentation
```

**A Tier 1 SOC analyst's routine with this dashboard**
1. Open **Alerts**, filter to *Open*, start with CRITICAL/HIGH.
2. Check whether the alert is valid: look at risk **and** confidence. `UNVERIFIED_HIGH_RISK` means "validate the intel first".
3. Open the linked threat → **enrichment**: first/last seen, source reliability, related indicators, ATT&CK behaviour.
4. **Scope**: search internal logs (proxy, DNS, email, EDR, VPN) for sightings. (In this project that's a documented step; nothing is contacted.)
5. **Decide**: *Escalate* to Tier 2/IR if there is evidence of impact → *Monitor* if credible but no impact → *Resolve* if handled → *False positive* if benign (e.g., shared cloud IP).
6. **Document** the reasoning in analyst notes; update status. Every change is audited.

## 34. Incident response awareness

High-level lifecycle (NIST SP 800-61 style; SANS uses PICERL; ISO 27035 uses different phase names, so terminology varies):

| Phase | Educational summary |
|---|---|
| **Preparation** | Plans, contacts, tooling, logging, backups, training, exercises |
| **Detection / Identification** | Triage alerts, confirm an incident, scope it, preserve evidence |
| **Containment** | Limit spread with *approved*, reversible steps (isolate host, disable account) |
| **Eradication** | Remove the root cause (patch, remove persistence) under change control |
| **Recovery** | Restore from known-good backups, monitor closely |
| **Lessons Learned** | Blameless review; improve controls, detections, training |

**Educational checklist for everyone** (also on the Awareness page):
- [ ] Report immediately through the official channel.
- [ ] Note what happened, when, which device/account.
- [ ] Disconnect a suspected infected device from the network, but don't wipe it or power it off unless told to.
- [ ] Don't delete suspicious emails/files (evidence).
- [ ] Don't contact or "hack back" the attacker.
- [ ] Follow the response team's instructions.

This project intentionally contains **no destructive response actions** (no automatic blocking, deletion or counter-actions).
