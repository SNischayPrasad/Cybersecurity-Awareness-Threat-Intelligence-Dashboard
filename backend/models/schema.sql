-- ============================================================================
-- Cybersecurity Awareness & Threat Intelligence Dashboard - SQLite schema
-- All threat data in this database is SYNTHETIC / DEMO ONLY.
-- ============================================================================
PRAGMA foreign_keys = ON;

-- Intelligence sources and their reliability grade (A-D).
CREATE TABLE IF NOT EXISTS sources (
    source_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name   TEXT NOT NULL UNIQUE,
    source_type   TEXT,
    reliability   TEXT NOT NULL CHECK (reliability IN ('A','B','C','D')),
    description   TEXT
);

-- One row per threat-intelligence record (an indicator WITH context).
CREATE TABLE IF NOT EXISTS threats (
    threat_id          TEXT PRIMARY KEY,
    threat_name        TEXT NOT NULL,
    category           TEXT NOT NULL,
    description        TEXT,
    severity           TEXT NOT NULL CHECK (severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
    impact_level       TEXT,
    risk_score         INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    confidence_score   INTEGER NOT NULL CHECK (confidence_score BETWEEN 0 AND 100),
    status             TEXT NOT NULL CHECK (status IN ('NEW','UNDER_REVIEW','MONITORING','CLOSED','FALSE_POSITIVE')),
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    observation_count  INTEGER NOT NULL DEFAULT 1,
    campaign_id        TEXT,
    region             TEXT,
    behavior_observed  TEXT,
    cve_id             TEXT,
    source_id          INTEGER REFERENCES sources(source_id),
    risk_breakdown_json TEXT,
    data_label         TEXT DEFAULT 'SYNTHETIC / DEMO ONLY',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

-- Indicators (IOCs). A threat has one primary indicator and may have more.
CREATE TABLE IF NOT EXISTS indicators (
    indicator_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id         TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    indicator_type    TEXT NOT NULL CHECK (indicator_type IN ('IP','DOMAIN','URL','FILE_HASH','EMAIL','CVE')),
    indicator_value   TEXT NOT NULL,
    normalized_value  TEXT NOT NULL,
    is_primary        INTEGER NOT NULL DEFAULT 1,
    first_seen        TEXT,
    last_seen         TEXT
);

-- MITRE ATT&CK mappings - only created when behaviour justifies them.
CREATE TABLE IF NOT EXISTS attack_mappings (
    mapping_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id              TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    tactic                 TEXT NOT NULL,
    technique              TEXT NOT NULL,
    technique_id_optional  TEXT,
    mapping_basis          TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                    TEXT NOT NULL UNIQUE,
    product_category          TEXT,
    description               TEXT,
    severity                  TEXT,
    cvss_score                REAL CHECK (cvss_score BETWEEN 0 AND 10),
    published_date            TEXT,
    patch_available           INTEGER NOT NULL DEFAULT 0,
    exploitation_status_demo  TEXT,
    asset_criticality         TEXT,
    exposure                  TEXT,
    handles_sensitive_data    INTEGER DEFAULT 0,
    priority_score            REAL,
    priority_band             TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT PRIMARY KEY,
    threat_id           TEXT REFERENCES threats(threat_id) ON DELETE SET NULL,
    vulnerability_cve   TEXT,
    indicator_value     TEXT,
    alert_type          TEXT NOT NULL,
    severity            TEXT NOT NULL,
    risk_score          INTEGER,
    confidence_score    INTEGER,
    description         TEXT,
    status              TEXT NOT NULL CHECK (status IN ('NEW','INVESTIGATING','MONITORING','RESOLVED','FALSE_POSITIVE')),
    observation_count   INTEGER NOT NULL DEFAULT 1,
    related_threat_ids  TEXT,
    first_observed      TEXT,
    last_observed       TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id   TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    author      TEXT NOT NULL DEFAULT 'analyst',
    note        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Lifecycle events: first seen, observations, risk change, investigation, closure.
CREATE TABLE IF NOT EXISTS threat_timeline (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id   TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    event_time  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    detail      TEXT
);

CREATE TABLE IF NOT EXISTS awareness_modules (
    module_id     TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    category      TEXT NOT NULL,
    content_json  TEXT NOT NULL
);

-- Quiz results are anonymous by design (no names, no emails).
CREATE TABLE IF NOT EXISTS quiz_results (
    result_id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    anonymous_user_id_optional  TEXT,
    overall_score               INTEGER NOT NULL,
    band                        TEXT,
    category_scores_json        TEXT,
    is_synthetic                INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL
);

-- Audit trail for every write made through the API.
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_role  TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    detail      TEXT,
    created_at  TEXT NOT NULL
);

-- Small key/value store for pipeline statistics (e.g., alert de-duplication).
CREATE TABLE IF NOT EXISTS app_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT
);

-- ----------------------------------------------------------------------------
-- Indexes: speed up the filters, searches and joins the dashboard uses most.
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_threats_category   ON threats(category);
CREATE INDEX IF NOT EXISTS idx_threats_severity   ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_status     ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_last_seen  ON threats(last_seen);
CREATE INDEX IF NOT EXISTS idx_threats_risk       ON threats(risk_score);
CREATE INDEX IF NOT EXISTS idx_threats_campaign   ON threats(campaign_id);
CREATE INDEX IF NOT EXISTS idx_indicators_value   ON indicators(normalized_value);
CREATE INDEX IF NOT EXISTS idx_indicators_threat  ON indicators(threat_id);
CREATE INDEX IF NOT EXISTS idx_indicators_type    ON indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_attack_threat      ON attack_mappings(threat_id);
CREATE INDEX IF NOT EXISTS idx_attack_technique   ON attack_mappings(technique_id_optional);
CREATE INDEX IF NOT EXISTS idx_alerts_status      ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_threat      ON alerts(threat_id);
CREATE INDEX IF NOT EXISTS idx_notes_threat       ON analyst_notes(threat_id);
CREATE INDEX IF NOT EXISTS idx_timeline_threat    ON threat_timeline(threat_id);
