# 09 · GitHub Upload Strategy & Screenshot Checklist

## 46. Repository setup

- **Repository name:** `Cybersecurity-Awareness-Threat-Intelligence-Dashboard`
- **Description:** Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.
- **Topics:** `cybersecurity` `threat-intelligence` `cti` `soc` `ioc` `mitre-attack` `security-awareness` `python` `flask` `fastapi` `vulnerability-management` `incident-response` `security-analytics` `defensive-security`
  (Only keep `fastapi` if you later build the FastAPI version. Honest topics matter to reviewers.)

### One-time Git setup
```powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

### Option 1: one commit per milestone (recommended for a clean history)
Run from the project folder. Each block stages the files that belong to that milestone.

```powershell
git init
git branch -M main

git add .gitignore requirements.txt .env.example pytest.ini backend/__init__.py backend/config.py backend/database.py backend/models backend/routes/__init__.py backend/services/__init__.py backend/utils/__init__.py data/__init__.py tests/__init__.py
git commit -m "Initialize cybersecurity threat intelligence dashboard"

git add data/generate_threat_data.py data/threat_intelligence_dataset.csv data/vulnerabilities.csv
git commit -m "Add synthetic threat intelligence dataset"

git add backend/services/ioc_validator.py
git commit -m "Implement IOC validation"

git add backend/services/enrichment_engine.py backend/services/ingestion.py backend/init_db.py
git commit -m "Add threat enrichment engine"

git add backend/services/risk_engine.py
git commit -m "Implement risk and confidence scoring"

git add backend/services/correlation_engine.py
git commit -m "Add threat correlation"

git add backend/services/alert_engine.py backend/routes/alerts.py
git commit -m "Implement security alert engine"

git add backend/services/attack_mapper.py backend/services/threat_categories.py
git commit -m "Add ATT&CK mapping module"

git add backend/services/vulnerability_service.py backend/routes/vulnerabilities.py frontend/vulnerabilities.html frontend/js/vulnerabilities.js
git commit -m "Build vulnerability awareness module"

git add backend/services/threat_service.py backend/utils backend/routes/dashboard.py backend/app.py frontend/css frontend/js/common.js frontend/index.html frontend/js/overview.js frontend/threat-dashboard.html frontend/js/dashboard.js frontend/attack.html frontend/js/attack.js frontend/alerts.html frontend/js/alerts.js
git commit -m "Create SOC threat dashboard"

git add backend/routes/threats.py
git commit -m "Add IOC search functionality"

git add frontend/threat-details.html frontend/js/details.js
git commit -m "Build threat investigation view"

git add awareness/modules.json frontend/awareness.html frontend/js/awareness.js backend/routes/awareness.py
git commit -m "Create cybersecurity awareness center"

git add awareness/quiz_questions.json frontend/quiz.html frontend/js/quiz.js
git commit -m "Add security awareness quiz"

git add backend/services/awareness_service.py
git commit -m "Implement awareness scoring"

git add backend/services/executive_service.py frontend/executive.html frontend/js/executive.js
git commit -m "Add executive cybersecurity summary"

git add tests
git commit -m "Implement automated tests"

git add README.md docs reports screenshots
git commit -m "Complete README and documentation"

git status   # should say: nothing to commit, working tree clean
```

> Tip: the commit history is proof of work. Even better, make these commits *as you study each module*, re-reading the file and running the matching tests before each commit.

### Option 2: single commit
```powershell
git init; git branch -M main
git add .
git commit -m "Initialize cybersecurity threat intelligence dashboard"
```

### Push to GitHub
1. Create an **empty** repository on github.com with the name above (no README, no .gitignore).
2. Then:
```powershell
git remote add origin https://github.com/<your-username>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
git push -u origin main
```
3. On GitHub: *About ⚙* → paste the description, add the topics, tick "Releases/Packages" off if unused.
4. Pin the repository on your GitHub profile.

**Before pushing, double-check:** `git status` must NOT list `.env` or `data/threat_intel.db` (both are git-ignored).

## 48. Screenshot / proof checklist

Save PNGs into `screenshots/` with these names (then reference them in the README's Screenshots section):

| # | What to capture | Filename |
|---|---|---|
| 1 | Project folder structure (VS Code explorer) | `01-project-structure.png` |
| 2 | System architecture (docs/02 diagram) | `02-system-architecture.png` |
| 3 | Synthetic dataset (CSV in Excel/VS Code) | `03-synthetic-dataset.png` |
| 4 | Threat dashboard (full page) | `04-threat-dashboard.png` |
| 5 | KPI cards | `05-threat-kpi-cards.png` |
| 6 | Severity distribution chart | `06-severity-distribution.png` |
| 7 | Threat-category chart | `07-threat-category-chart.png` |
| 8 | IOC type distribution | `08-ioc-distribution.png` |
| 9 | Threat timeline (detail page) | `09-threat-timeline.png` |
| 10 | Risk distribution | `10-risk-distribution.png` |
| 11 | Confidence distribution | `11-confidence-distribution.png` |
| 12 | IOC search box | `12-ioc-search.png` |
| 13 | IOC search result for 198.51.100.25 | `13-ioc-search-result.png` |
| 14 | Threat detail page (THR-…-001) | `14-threat-detail-page.png` |
| 15 | Risk score + breakdown table | `15-risk-score-breakdown.png` |
| 16 | Confidence score + interpretation | `16-confidence-score.png` |
| 17 | Related indicators / related threats | `17-related-indicators.png` |
| 18 | ATT&CK mapping (detail + ATT&CK page) | `18-attack-mapping.png` |
| 19 | Vulnerability dashboard | `19-vulnerability-dashboard.png` |
| 20 | Alert dashboard (KPIs 570 → 470) | `20-alert-dashboard.png` |
| 21 | Alert investigation (status change) | `21-alert-investigation.png` |
| 22 | Analyst notes | `22-analyst-notes.png` |
| 23 | Awareness Center | `23-awareness-center.png` |
| 24 | Phishing module opened | `24-phishing-module.png` |
| 25 | Password/MFA module | `25-password-mfa-module.png` |
| 26 | Ransomware-awareness module | `26-ransomware-module.png` |
| 27 | Quiz | `27-security-quiz.png` |
| 28 | Quiz result (score + band) | `28-quiz-result.png` |
| 29 | Awareness category scores | `29-awareness-category-scores.png` |
| 30 | Learning recommendations | `30-learning-recommendations.png` |
| 31 | Executive dashboard | `31-executive-dashboard.png` |
| 32 | Automated tests (`pytest -v`, 40 passed) | `32-automated-tests.png` |
| 33 | API response (browser/Postman JSON) | `33-api-response.png` |
| 34 | Database (DB Browser for SQLite) | `34-database-tables.png` |
| 35 | GitHub commit history | `35-github-commits.png` |
| 36 | GitHub repository page | `36-github-repository.png` |
| 37 | README preview on GitHub | `37-readme-preview.png` |

Tips: use a 1440px-wide browser window, crop to the relevant panel, and never include real personal data (your analyst key, email, etc.) in screenshots.
