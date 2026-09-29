# 06 · Local Execution (15 steps) & Safe Demonstration Scenario

## 41. Run it locally

Commands are shown for **Windows PowerShell** (your machine) and **macOS/Linux**. Python 3.10+ is required (tested on 3.13).

**STEP 1: Create / enter the project folder**
```powershell
cd C:\Users\<you>\Projects
git clone https://github.com/<your-username>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```
(Or just `cd` into the folder you already have.)

**STEP 2: Create and activate a virtual environment**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # PowerShell
# If blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
```bash
python3 -m venv .venv && source .venv/bin/activate      # macOS / Linux
```

**STEP 3: Install dependencies**
```powershell
pip install -r requirements.txt
Copy-Item .env.example .env            # then edit the two API keys
```

**STEP 4: Generate synthetic threat data**
```powershell
python data/generate_threat_data.py
```
Expected: `Wrote 2004 threat records ... Demo record THR-2026-001: risk=78 confidence=85 severity=HIGH`

**STEP 5: Initialise the database**
```powershell
python -m backend.init_db
```
Expected: JSON report with `"ingested": 2004, "rejected": 0` and alert counts.

**STEP 6: Start the backend**
```powershell
python -m backend.app
```

**STEP 7: Start the frontend**. Nothing extra to do: Flask serves `frontend/` on the same port.

**STEP 8: Open the threat dashboard** at <http://127.0.0.1:5000/threat-dashboard.html>

**STEP 9: Search a synthetic IOC.** Type `198.51.100.25` in *IOC search*. Expected: Known YES, Risk 78/100, HIGH, Confidence 85%, Phishing, MONITORING.

**STEP 10: Open threat details.** Click *Primary record* or open <http://127.0.0.1:5000/threat-details.html?id=THR-2026-001>.

**STEP 11: Review ATT&CK mapping** on the detail page (T1566.002) and the **ATT&CK** page. Click a technique to list its records.

**STEP 12: Review vulnerabilities** on the **Vulnerabilities** page. Compare CVE-2099-0001 (CVSS 9.8 → P3) vs CVE-2099-0002 (CVSS 8.1 → P1) and try the calculator.

**STEP 13: Open the Awareness Center** and open a few modules (Phishing, MFA, Ransomware).

**STEP 14: Complete the quiz** (40 questions) on the **Quiz** page.

**STEP 15: View your awareness score**: overall score, band, category scores, weakest areas, recommended modules with links.

**Run the tests**
```powershell
python -m pytest -v
```

**Analyst actions:** paste the analyst key from your `.env` into the *Analyst API key* box (top right) → *Set key*. You can now add notes and change statuses. Without a key the UI is read-only.

> The dashboard's dates are relative to the day you generate the data. The demo ID uses that year (`THR-<year>-001`).

---

## 42. Safe demonstration scenario

| Field | Value |
|---|---|
| Threat ID | `THR-2026-001` |
| Threat name | Synthetic Credential Phishing Campaign |
| Category | PHISHING |
| Indicator type | DOMAIN |
| Indicator | `login-check.invalid` (the `.invalid` TLD is reserved and can never resolve) |
| Severity | HIGH |
| Risk | **78/100**, computed by the risk engine, not hard-coded |
| Confidence | **85/100**: vendor source (B) + 3 corroborating sources + validated + behavioural context + analyst review |
| First seen / Last seen | 20 days / 2 days before the dataset date |
| Status | MONITORING |
| Related indicators | `198.51.100.25` (documentation-range IP), lure URL, sender address, all in campaign `CMP-DEMO-001` |
| ATT&CK mapping | **Initial Access → T1566.002 Phishing: Spearphishing Link**. Justified because the behaviour "email lure containing a link" was observed. |
| Analyst notes | "Indicator appears in multiple synthetic phishing observations." (+2 more) |
| Timeline | FIRST_SEEN → RISK_ASSESSED 62 → RISK_INCREASED 62→78 after correlation → NEW_OBSERVATIONS → RISK_ASSESSED 78 → INVESTIGATION_STARTED → MONITORING |
| Evidence level | **THREAT**, not INCIDENT (no confirmed impact) |

**Recommended actions (shown on the page)**
- Review related internal logs (proxy, DNS, email, authentication) for sightings.
- Check whether any sightings were authorised or expected.
- Review email-security telemetry for messages referencing this indicator.
- Increase phishing awareness (link to the Phishing module).
- Monitor for related indicators in the same cluster.

**Do NOT visit the domain.** The dashboard shows it defanged (`login-check[.]invalid`) and never contacts it.

### Demo script (3 minutes, for a viva or video)
1. Overview → explain the evidence ladder (observation ≠ incident).
2. Dashboard → KPI cards, then click the *Phishing* bar to filter.
3. IOC search `198.51.100.25` → "database lookup only".
4. Open THR-…-001 → risk vs confidence, risk breakdown table, ATT&CK justification, timeline, related cluster.
5. Alerts → 570 → 470 alert reduction and the 100-sighting alert with observation count 100.
6. Vulnerabilities → CVSS 9.8 P3 vs CVSS 8.1 P1.
7. Quiz → submit → weakest areas → recommended module.
8. Executive → plain-language headline and priorities.
