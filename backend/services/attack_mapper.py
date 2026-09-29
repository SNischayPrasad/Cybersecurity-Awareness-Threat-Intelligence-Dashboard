"""
MITRE ATT&CK Mapper
===================

IOC  -> tells us WHAT artifact was observed (an IP, a hash, a domain).
ATT&CK -> helps describe HOW the observed *behaviour* relates to known
adversary tactics and techniques.

Rule used in this project: we map a record to ATT&CK ONLY when a specific
behaviour was observed (`behavior_observed`). A bare "this IP is on a feed"
record gets NO mapping, because an indicator alone is not a behaviour.

Technique IDs below are from MITRE ATT&CK Enterprise (v15+ naming). Always
verify at https://attack.mitre.org before relying on them in production.
"""
from __future__ import annotations

# behaviour code -> (tactic, technique name, technique ID, human description)
BEHAVIOR_TO_ATTACK = {
    "email_link_lure": ("Initial Access", "Phishing: Spearphishing Link", "T1566.002",
                        "Email lure containing a link was observed."),
    "email_attachment_lure": ("Initial Access", "Phishing: Spearphishing Attachment", "T1566.001",
                              "Email lure carrying an attachment was observed."),
    "voice_callback_lure": ("Initial Access", "Phishing: Spearphishing Voice", "T1566.004",
                            "Message urged the recipient to call a fake support number."),
    "credential_harvest_page": ("Reconnaissance", "Phishing for Information: Spearphishing Link", "T1598.003",
                                "A fake sign-in page collecting credentials was reported."),
    "user_opened_file": ("Execution", "User Execution: Malicious File", "T1204.002",
                         "A user opened a file that security tooling flagged."),
    "web_c2_beaconing": ("Command and Control", "Application Layer Protocol: Web Protocols", "T1071.001",
                         "Periodic outbound web traffic consistent with beaconing was observed."),
    "tool_download": ("Command and Control", "Ingress Tool Transfer", "T1105",
                      "Download of an additional tool from external infrastructure was observed."),
    "autostart_persistence": ("Persistence",
                              "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                              "T1547.001", "A new autostart entry was created by an untrusted program."),
    "files_encrypted": ("Impact", "Data Encrypted for Impact", "T1486",
                        "Mass file encryption behaviour was reported."),
    "backup_deletion": ("Impact", "Inhibit System Recovery", "T1490",
                        "Attempts to remove backups/shadow copies were reported."),
    "password_spraying": ("Credential Access", "Brute Force: Password Spraying", "T1110.003",
                          "Few passwords tried across many accounts."),
    "brute_force": ("Credential Access", "Brute Force", "T1110",
                    "Many failed logins against the same account(s)."),
    "mfa_fatigue": ("Credential Access", "Multi-Factor Authentication Request Generation", "T1621",
                    "Repeated unexpected MFA push prompts were reported by users."),
    "valid_account_login_anomaly": ("Initial Access", "Valid Accounts", "T1078",
                                    "Successful login with legitimate credentials from unusual context."),
    "session_cookie_theft": ("Credential Access", "Steal Web Session Cookie", "T1539",
                             "Evidence of session token reuse from another location."),
    "public_app_exploit_attempt": ("Initial Access", "Exploit Public-Facing Application", "T1190",
                                   "Exploit-like requests against an internet-facing app were logged."),
    "drive_by_site": ("Initial Access", "Drive-by Compromise", "T1189",
                      "Users were redirected through a compromised website."),
    "external_scanning": ("Reconnaissance", "Active Scanning", "T1595",
                          "Systematic probing of our public services was logged."),
    "remote_service_access": ("Initial Access", "External Remote Services", "T1133",
                              "Login attempts against remote-access services (VPN/RDP gateway)."),
    "ddos_traffic": ("Impact", "Network Denial of Service", "T1498",
                     "Traffic flood degrading service availability."),
    "cloud_storage_exposure": ("Collection", "Data from Cloud Storage", "T1530",
                               "Access to an improperly exposed cloud storage location."),
    "exfil_web_service": ("Exfiltration", "Exfiltration Over Web Service", "T1567",
                          "Large uploads to an unsanctioned web service."),
    "exfil_c2": ("Exfiltration", "Exfiltration Over C2 Channel", "T1041",
                 "Data volume sent over an existing suspicious channel."),
    "impersonation_pretext": ("Defense Evasion", "Impersonation", "T1656",
                              "Sender impersonated a trusted executive or supplier."),
}

# Behaviours that are NOT enough to justify an ATT&CK mapping.
UNMAPPED_BEHAVIORS = {
    "reputation_only": "Indicator appeared on a reputation feed only - no behaviour observed.",
    "": "No behavioural context available.",
}

ATTACK_TACTICS_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]

ATTACK_VERSION_NOTE = ("Mapped to MITRE ATT&CK Enterprise (v15+ terminology). "
                       "Mappings are behaviour-based and only applied when context exists.")


def map_to_attack(behavior_observed: str | None) -> dict | None:
    """Return an ATT&CK mapping dict for an observed behaviour, or None.

    None means "insufficient context" - we deliberately do not guess.
    """
    key = (behavior_observed or "").strip().lower()
    if key not in BEHAVIOR_TO_ATTACK:
        return None
    tactic, technique, technique_id, basis = BEHAVIOR_TO_ATTACK[key]
    return {
        "tactic": tactic,
        "technique": technique,
        "technique_id_optional": technique_id,
        "mapping_basis": basis,
    }


def mapping_explanation(behavior_observed: str | None) -> str:
    key = (behavior_observed or "").strip().lower()
    if key in BEHAVIOR_TO_ATTACK:
        return BEHAVIOR_TO_ATTACK[key][3]
    return UNMAPPED_BEHAVIORS.get(key, "Behaviour not recognised - no mapping applied.")


def attack_technique_url(technique_id: str | None) -> str | None:
    """Reference link for analysts (displayed, never fetched by the app)."""
    if not technique_id:
        return None
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
