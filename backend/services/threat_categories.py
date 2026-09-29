"""
Threat category knowledge base.

Each category carries defensive knowledge only: description, common
indicators, potential impact, defensive controls and awareness advice.
No exploitation instructions are included.
"""

THREAT_CATEGORIES = {
    "PHISHING": {
        "label": "Phishing",
        "description": "Deceptive messages that trick people into revealing credentials, "
                       "opening harmful files or approving payments.",
        "common_indicators": ["Look-alike sender domains", "Links to fake sign-in pages",
                              "Unexpected attachments", "Urgent or threatening language"],
        "potential_impact": ["Stolen credentials", "Malware delivery", "Payment fraud"],
        "defensive_controls": ["Email filtering and link rewriting", "SPF/DKIM/DMARC",
                               "Phishing-resistant MFA", "One-click 'Report phishing' button"],
        "awareness": "Pause on urgency, verify through a trusted channel, report suspicious messages.",
        "awareness_module": "phishing",
    },
    "MALWARE": {
        "label": "Malware",
        "description": "Malicious software designed to damage, spy on, or gain unauthorised access to systems.",
        "common_indicators": ["Known-bad file hashes", "Beaconing to unusual domains",
                              "New autostart entries", "Unsigned binaries in user folders"],
        "potential_impact": ["Data theft", "Remote control of devices", "Further compromise"],
        "defensive_controls": ["Endpoint detection & response (EDR)", "Application allow-listing",
                               "Patching", "Least privilege"],
        "awareness": "Only install software from trusted sources and keep devices updated.",
        "awareness_module": "software-updates",
    },
    "RANSOMWARE": {
        "label": "Ransomware",
        "description": "Malware that encrypts or steals data and demands payment for its return.",
        "common_indicators": ["Mass file renames", "Backup deletion attempts",
                              "Ransom notes", "Unusual admin tool use"],
        "potential_impact": ["Operational downtime", "Data loss", "Extortion", "Regulatory exposure"],
        "defensive_controls": ["Offline/immutable backups", "Network segmentation", "MFA on remote access",
                               "EDR", "Tested incident response plan"],
        "awareness": "Report suspicious files immediately; never try to 'fix' an infected device alone.",
        "awareness_module": "ransomware",
    },
    "CREDENTIAL_THREATS": {
        "label": "Credential Theft",
        "description": "Attempts to steal, guess or reuse account credentials.",
        "common_indicators": ["Password spraying from a single IP", "Fake login pages",
                              "Credential stuffing bursts", "Leaked password reports"],
        "potential_impact": ["Account takeover", "Unauthorised data access"],
        "defensive_controls": ["MFA", "Password manager adoption", "Breached-password screening",
                               "Login anomaly detection", "Account lockout / throttling"],
        "awareness": "Use unique passwords with a password manager and enable MFA everywhere.",
        "awareness_module": "password-security",
    },
    "WEB_THREATS": {
        "label": "Web Threats",
        "description": "Threats delivered through websites: compromised sites, malicious redirects "
                       "and attacks against web applications.",
        "common_indicators": ["Suspicious redirect chains", "Exploit-like request patterns in web logs",
                              "Newly registered look-alike sites"],
        "potential_impact": ["Drive-by infection", "Web application compromise", "Data leakage"],
        "defensive_controls": ["Web application firewall", "Secure web gateway / DNS filtering",
                               "Secure coding and patching", "Browser isolation"],
        "awareness": "Check URLs carefully, keep browsers updated, avoid unofficial downloads.",
        "awareness_module": "safe-browsing",
    },
    "NETWORK_THREATS": {
        "label": "Network Threats",
        "description": "Suspicious network activity such as scanning, flooding or remote-access abuse.",
        "common_indicators": ["Port scanning sources", "Traffic floods",
                              "Repeated remote-access login failures"],
        "potential_impact": ["Service disruption", "Reconnaissance for later attacks"],
        "defensive_controls": ["Firewall policy review", "IDS/IPS", "DDoS protection",
                               "VPN with MFA", "Network segmentation"],
        "awareness": "Avoid untrusted Wi-Fi for work and use the company VPN.",
        "awareness_module": "secure-wifi",
    },
    "VULNERABILITY_EXPOSURE": {
        "label": "Vulnerability Exploitation Awareness",
        "description": "Unpatched weaknesses in software that adversaries could abuse.",
        "common_indicators": ["CVE references in intelligence", "Exploit-like scans against exposed services"],
        "potential_impact": ["Initial access for attackers", "Service compromise"],
        "defensive_controls": ["Asset inventory", "Risk-based patch prioritisation",
                               "Virtual patching (WAF/IPS)", "Reducing internet exposure"],
        "awareness": "Install updates promptly - most exploited vulnerabilities already have patches.",
        "awareness_module": "software-updates",
    },
    "SOCIAL_ENGINEERING": {
        "label": "Social Engineering",
        "description": "Manipulating people - by email, phone, chat or in person - into bypassing security.",
        "common_indicators": ["Executive impersonation", "Pretext phone calls", "Gift-card requests",
                              "Pressure to skip normal process"],
        "potential_impact": ["Fraudulent payments", "Credential disclosure", "Physical access"],
        "defensive_controls": ["Call-back verification procedures", "Dual approval for payments",
                               "Awareness training", "Clear reporting channels"],
        "awareness": "Verify identity through a known number; it is always OK to say 'let me call you back'.",
        "awareness_module": "social-engineering",
    },
    "DATA_EXPOSURE": {
        "label": "Data Exposure",
        "description": "Sensitive data made accessible to the wrong people through misconfiguration or theft.",
        "common_indicators": ["Publicly readable storage buckets", "Unusual large uploads",
                              "Data found on paste sites"],
        "potential_impact": ["Privacy breach", "Regulatory penalties", "Reputational damage"],
        "defensive_controls": ["Data loss prevention (DLP)", "Cloud posture management",
                               "Access reviews", "Encryption"],
        "awareness": "Share data only through approved tools and only with people who need it.",
        "awareness_module": "data-privacy",
    },
    "ACCOUNT_SECURITY": {
        "label": "Account Takeover Risk",
        "description": "Signs that an account may be misused: odd logins, MFA fatigue, session theft.",
        "common_indicators": ["Impossible-travel logins", "MFA push floods", "Session token reuse"],
        "potential_impact": ["Unauthorised access", "Business email compromise", "Data theft"],
        "defensive_controls": ["Phishing-resistant MFA / passkeys", "Number-matching MFA",
                               "Conditional access", "Session revocation"],
        "awareness": "Never approve an MFA prompt you did not start - report it instead.",
        "awareness_module": "mfa",
    },
}

CATEGORY_CODES = tuple(THREAT_CATEGORIES.keys())


def recommended_actions(category: str, status: str, indicator_type: str) -> list[str]:
    """Defensive, non-destructive next steps for an analyst."""
    actions = [
        "Review related internal logs (proxy, DNS, email, authentication) for sightings.",
        "Check whether any sightings were authorised or expected (e.g., security testing).",
    ]
    if indicator_type in ("DOMAIN", "URL", "EMAIL"):
        actions.append("Review email-security telemetry for messages referencing this indicator.")
    if indicator_type == "FILE_HASH":
        actions.append("Search EDR telemetry for the hash. Never download or execute the file.")
    if indicator_type == "IP":
        actions.append("Search firewall/VPN logs for connections; consider a monitored block-list entry "
                       "after approval.")
    if indicator_type == "CVE":
        actions.append("Confirm affected assets in inventory and follow the patch-priority workflow.")
    cat = THREAT_CATEGORIES.get(category)
    if cat:
        actions.append(f"Reinforce awareness: {cat['awareness']}")
    if status in ("NEW", "UNDER_REVIEW"):
        actions.append("Complete triage and record the decision in analyst notes.")
    if status == "MONITORING":
        actions.append("Monitor for related indicators in the same cluster.")
    if status == "FALSE_POSITIVE":
        actions = ["Document why this was a false positive and tune the rule/feed to reduce noise."]
    if status == "CLOSED":
        actions = ["No active action. Keep for historical context and lessons learned."]
    return actions
