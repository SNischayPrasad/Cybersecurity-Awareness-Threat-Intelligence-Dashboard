# 02 · System Architecture, Tech Stack & Folder Structure

## 37. System architecture

```
          Synthetic / Public Defensive Threat Data  (data/*.csv)
                              ↓
                     Data Ingestion Layer          services/ingestion.py
                              ↓
                        Normalization               threat_service.normalize_threat_input
                              ↓
                  IOC Validation / Extraction       services/ioc_validator.py
                              ↓
                      Threat Enrichment             services/enrichment_engine.py
                              ↓
                  Risk + Confidence Engine          services/risk_engine.py
                              ↓
                     Correlation Engine             services/correlation_engine.py
                              ↓
        ┌─────────────────────┼──────────────────────┐
        ↓                     ↓                      ↓
    Threat DB            Alert Engine          ATT&CK Mapping
 (SQLite schema.sql)  services/alert_engine   services/attack_mapper
        ↓                     ↓                      ↓
        └─────────────────────┼──────────────────────┘
                              ↓
                SOC Dashboard (Flask REST API + HTML/JS/Chart.js)
                              ↓
                           Analyst

Parallel track (human defense):

   awareness/modules.json  →  Learning Modules  (awareness.html)
            ↓
   awareness/quiz_questions.json → Quiz Engine (awareness_service.score_quiz)
            ↓
   Awareness Score (0-100, bands)  →  generate_learning_recommendations()
            ↓
   Executive Summary (executive_service) ← also consumes threat + vulnerability data
```

**Request flow example (IOC search):** browser → `GET /api/indicators/search?q=198.51.100.25` → `routes/threats.py` → `enrichment_engine.enrich_indicator()` → `validate_indicator()` (syntax only) → SQL lookups on `indicators`, `threats`, `alerts`, `attack_mappings`, `analyst_notes` → JSON → rendered with `textContent` (XSS-safe). **No socket is ever opened to the searched indicator**, and test 17 proves it by making any network call fail.

## 38. Technology stack options

| Option | Frontend | Backend | DB | Analytics | Charts | Good for |
|---|---|---|---|---|---|---|
| **A – Beginner (chosen)** | HTML, CSS, JavaScript | Python Flask | SQLite | pandas | Chart.js | Learning fundamentals, zero setup |
| B – Modern | React | FastAPI | PostgreSQL | pandas | Recharts | Typed APIs, component UIs |
| C – Advanced | React | FastAPI | PostgreSQL + Redis | pandas | Recharts | Production-style, Docker, caching, queues |

**Recommendation: Option A.** You can read and explain every line (no build tools, no bundler, no DB server), it runs on any laptop with one command, and the concepts (REST, SQL, RBAC, validation, scoring) transfer directly to B or C. The code is structured (routes → services → database) so a later migration to FastAPI or PostgreSQL only replaces the edges, not the engines. Upgrading is listed under Future Improvements.

## 39. Folder structure

```
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
│
├── backend/                     Python server
│   ├── app.py                   Flask app factory; serves API + frontend; security headers; rate limit
│   ├── config.py                Settings from environment variables / .env
│   ├── database.py              SQLite connection helpers, audit log, metadata
│   ├── init_db.py               CLI: build database from CSVs (python -m backend.init_db)
│   ├── routes/                  Thin HTTP layer (one blueprint per area)
│   │   ├── threats.py           /api/threats, /api/indicators/*, notes
│   │   ├── dashboard.py         /api/dashboard/*, /api/attack/*, /api/executive/*, /api/health
│   │   ├── alerts.py            /api/alerts
│   │   ├── vulnerabilities.py   /api/vulnerabilities
│   │   └── awareness.py         /api/awareness/*, /api/quiz
│   ├── models/
│   │   └── schema.sql           Tables, constraints, indexes
│   ├── services/                Business logic (unit-tested)
│   │   ├── threat_service.py    Normalisation, storage, queries, lifecycle, dashboard analytics
│   │   ├── ioc_validator.py     Syntax validation (IPv4/6, domain, URL, hashes, email, CVE), defang
│   │   ├── enrichment_engine.py Local-only enrichment
│   │   ├── risk_engine.py       Risk, confidence, source reliability
│   │   ├── correlation_engine.py Union-find clustering; related threats
│   │   ├── alert_engine.py      Alert rules, alert correlation, storage, status updates
│   │   ├── attack_mapper.py     Behaviour → ATT&CK mapping
│   │   ├── vulnerability_service.py Contextual patch priority
│   │   ├── awareness_service.py Modules, quiz scoring, awareness score, recommendations
│   │   ├── executive_service.py Executive summary
│   │   ├── threat_categories.py Category knowledge base + recommended actions
│   │   └── ingestion.py         CSV → normalise → validate → score → store pipeline
│   └── utils/
│       ├── security.py          sanitize_text, API-key RBAC, rate limiter, security headers
│       └── helpers.py           JSON error helper, body parsing
│
├── frontend/                    Static site served by Flask
│   ├── index.html               Overview: evidence ladder, pipeline, quick IOC lookup
│   ├── threat-dashboard.html    SOC dashboard: 7 KPI cards, 10 charts, IOC search, threat table
│   ├── threat-details.html      Investigation view for one threat
│   ├── attack.html              ATT&CK tactics/techniques + matrix + drill-down
│   ├── vulnerabilities.html     Vulnerability register + priority calculator
│   ├── alerts.html              Alert queue, alert fatigue metrics, SOC workflow
│   ├── awareness.html           Awareness Center (15 modules) + incident-response checklist
│   ├── quiz.html                40-question quiz + score + recommendations
│   ├── executive.html           Executive cybersecurity summary
│   ├── css/style.css            SOC console theme
│   └── js/                      One script per page + common.js (safe DOM, API, charts)
│
├── awareness/
│   ├── modules.json             15 awareness modules (content lives in data, not code)
│   └── quiz_questions.json      40 questions with answers + explanations
│
├── data/
│   ├── generate_threat_data.py  Synthetic dataset generator (safe indicators only)
│   ├── threat_intelligence_dataset.csv   2,004 synthetic records
│   └── vulnerabilities.csv      62 synthetic CVE-2099-* records
│
├── tests/                       40 pytest tests (fresh temp DB each run)
├── screenshots/                 Put your proof screenshots here (see docs/09)
├── reports/                     PROJECT_REPORT.md
├── docs/                        All documentation
├── README.md
├── requirements.txt
├── pytest.ini
├── .env.example                 Template for secrets (copy to .env)
└── .gitignore                   Keeps .env, venv and the generated DB out of Git
```

**Why separate routes and services?** Routes only translate HTTP ↔ Python (parse input, pick a status code). Services hold the security logic and are tested directly, which is the same layering used in industry codebases.
