"""
IOC Validation Engine
=====================

`validate_indicator()` answers ONE question:

    "Is this value a syntactically valid indicator of type X?"

It NEVER answers "Is this malicious?" and it NEVER contacts the indicator.
There is no DNS lookup, no HTTP request, no ping - validation is pure string
analysis, so it is safe to run on hostile input.

Supported types
---------------
IP (IPv4 / IPv6), DOMAIN, URL, FILE_HASH (MD5 / SHA-1 / SHA-256 formats),
EMAIL (sender address), CVE (CVE ID format).
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

# Canonical indicator types used everywhere in the project.
INDICATOR_TYPES = ("IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL", "CVE")

HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}
HEX_RE = re.compile(r"^[0-9a-f]+$")
CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
EMAIL_LOCAL_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")

# Address ranges reserved for documentation (RFC 5737 / RFC 3849).
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# Domains reserved for documentation/testing (RFC 2606 / RFC 6761).
RESERVED_DOMAIN_SUFFIXES = (
    "example.com", "example.org", "example.net",
    ".example", ".invalid", ".test", ".localhost",
)


def refang(value: str) -> str:
    """Undo common "defanging" (e.g. hxxp://evil[.]example) so we can validate.

    Analysts defang indicators so nobody clicks them by accident. We refang
    ONLY in memory to check syntax - nothing is ever visited.
    """
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    return v


def defang(value: str) -> str:
    """Make an indicator non-clickable for display (http -> hxxp, . -> [.])."""
    if not value:
        return value
    v = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    # Only defang dots in hostnames/IPs/emails, not in hashes/CVE IDs.
    if CVE_RE.match(value.upper()) or HEX_RE.match(value.lower()):
        return value
    return v.replace(".", "[.]")


def _result(valid, indicator_type, normalized, notes, subtype=None, raw=""):
    return {
        "valid": valid,
        "indicator_type": indicator_type,
        "subtype": subtype,
        "normalized_value": normalized,
        "validation_notes": notes,
        "input_value": raw,
    }


def is_documentation_ip(ip_obj) -> bool:
    return any(ip_obj in net for net in DOCUMENTATION_NETWORKS if ip_obj.version == net.version)


def is_reserved_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    for suffix in RESERVED_DOMAIN_SUFFIXES:
        if suffix.startswith("."):          # a reserved TLD such as .invalid
            if d.endswith(suffix):
                return True
        elif d == suffix or d.endswith("." + suffix):  # example.com and its subdomains
            return True
    return False


# ---------------------------------------------------------------------------
# Individual validators
# ---------------------------------------------------------------------------
def validate_ip(value: str) -> dict:
    raw = value
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return _result(False, "IP", None, ["Not a valid IPv4 or IPv6 address."], raw=raw)
    notes = [f"Syntactically valid IPv{ip.version} address."]
    if is_documentation_ip(ip):
        notes.append("Address is in a documentation range (safe demo value).")
    elif ip.is_private:
        notes.append("Private/internal address - context matters, may be your own asset.")
    elif ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        notes.append("Special-purpose address range.")
    notes.append("Validation does not mean the address is malicious. No connection was made.")
    return _result(True, "IP", ip.compressed, notes, subtype=f"IPv{ip.version}", raw=raw)


def validate_domain(value: str) -> dict:
    raw = value
    d = value.strip().lower().rstrip(".")
    notes = []
    if not d or len(d) > 253 or " " in d:
        return _result(False, "DOMAIN", None, ["Empty, too long (>253), or contains spaces."], raw=raw)
    try:
        d = d.encode("idna").decode("ascii")  # handle internationalised names safely
    except UnicodeError:
        return _result(False, "DOMAIN", None, ["Domain could not be IDNA-encoded."], raw=raw)
    labels = d.split(".")
    if len(labels) < 2:
        return _result(False, "DOMAIN", None, ["A domain needs at least two labels (name.tld)."], raw=raw)
    if not all(LABEL_RE.match(label) for label in labels):
        return _result(False, "DOMAIN", None,
                       ["Each label must be 1-63 chars of a-z, 0-9 or '-', not starting/ending with '-'."],
                       raw=raw)
    if not TLD_RE.match(labels[-1]):
        return _result(False, "DOMAIN", None, ["Top-level domain is not valid."], raw=raw)
    notes.append("Syntactically valid domain name.")
    if is_reserved_domain(d):
        notes.append("Domain is reserved for documentation/testing (safe demo value).")
    notes.append("No DNS lookup was performed. Validity is not maliciousness.")
    return _result(True, "DOMAIN", d, notes, raw=raw)


def validate_url(value: str) -> dict:
    raw = value
    v = refang(value)
    try:
        parts = urlsplit(v)
    except ValueError:
        return _result(False, "URL", None, ["URL could not be parsed."], raw=raw)
    if parts.scheme.lower() not in ("http", "https", "ftp"):
        return _result(False, "URL", None, ["URL must start with http://, https:// or ftp://."], raw=raw)
    host = parts.hostname or ""
    if not host:
        return _result(False, "URL", None, ["URL has no host."], raw=raw)
    host_check = validate_ip(host) if _looks_like_ip(host) else validate_domain(host)
    if not host_check["valid"]:
        return _result(False, "URL", None, ["URL host is invalid: "] + host_check["validation_notes"], raw=raw)
    netloc = host_check["normalized_value"]
    if ":" in netloc:  # IPv6 host needs brackets back
        netloc = f"[{netloc}]"
    if parts.port:
        netloc += f":{parts.port}"
    normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    notes = ["Syntactically valid URL.", "The URL was NOT visited or fetched."]
    if any("documentation" in n for n in host_check["validation_notes"]):
        notes.append("Host is a reserved documentation/testing name.")
    return _result(True, "URL", normalized, notes, subtype=parts.scheme.lower(), raw=raw)


def validate_hash(value: str) -> dict:
    raw = value
    v = value.strip().lower()
    algo = HASH_LENGTHS.get(len(v))
    if not algo or not HEX_RE.match(v):
        return _result(False, "FILE_HASH", None,
                       ["Hash must be 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hexadecimal characters."], raw=raw)
    notes = [f"Valid {algo}-format hash.",
             "A hash is only a fingerprint - no file is downloaded, opened or executed."]
    if algo in ("MD5", "SHA1"):
        notes.append(f"{algo} is collision-prone; prefer SHA-256 when available.")
    return _result(True, "FILE_HASH", v, notes, subtype=algo, raw=raw)


def validate_cve(value: str) -> dict:
    raw = value
    v = value.strip().upper()
    if not CVE_RE.match(v):
        return _result(False, "CVE", None, ["CVE IDs look like CVE-YYYY-NNNN (4 or more digits)."], raw=raw)
    notes = ["Valid CVE ID format."]
    if v.startswith("CVE-2099-"):
        notes.append("CVE-2099-* IDs in this project are SYNTHETIC demo records, not real CVEs.")
    return _result(True, "CVE", v, notes, raw=raw)


def validate_email(value: str) -> dict:
    raw = value
    v = refang(value).lower()
    if v.count("@") != 1:
        return _result(False, "EMAIL", None, ["Email must contain exactly one '@'."], raw=raw)
    local, domain = v.split("@")
    if not EMAIL_LOCAL_RE.match(local) or local.startswith(".") or local.endswith("."):
        return _result(False, "EMAIL", None, ["Email local part is invalid."], raw=raw)
    dom = validate_domain(domain)
    if not dom["valid"]:
        return _result(False, "EMAIL", None, ["Email domain is invalid."] + dom["validation_notes"], raw=raw)
    notes = ["Syntactically valid sender address.", "No email was sent and the domain was not queried."]
    return _result(True, "EMAIL", f"{local}@{dom['normalized_value']}", notes, raw=raw)


def _looks_like_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v.strip())
        return True
    except ValueError:
        return False


VALIDATORS = {
    "IP": validate_ip,
    "DOMAIN": validate_domain,
    "URL": validate_url,
    "FILE_HASH": validate_hash,
    "EMAIL": validate_email,
    "CVE": validate_cve,
}


def detect_indicator_type(value: str) -> str | None:
    """Best-effort guess of the indicator type from its shape."""
    v = refang(value or "").strip()
    if not v:
        return None
    if CVE_RE.match(v.upper()):
        return "CVE"
    if _looks_like_ip(v):
        return "IP"
    if len(v) in HASH_LENGTHS and HEX_RE.match(v.lower()):
        return "FILE_HASH"
    if "://" in v:
        return "URL"
    if "@" in v:
        return "EMAIL"
    if "." in v:
        return "DOMAIN"
    return None


def validate_indicator(value, expected_type: str | None = None) -> dict:
    """Validate an indicator's SYNTAX.

    Args:
        value: the raw indicator string (defanged input is accepted).
        expected_type: optional - one of INDICATOR_TYPES. If omitted the type is auto-detected.

    Returns:
        dict with keys: valid, indicator_type, subtype, normalized_value, validation_notes, input_value
    """
    if value is None or not isinstance(value, str) or not value.strip():
        return _result(False, expected_type, None, ["Empty indicator value."], raw=value or "")
    if len(value) > 2048:
        return _result(False, expected_type, None, ["Indicator is too long (max 2048 characters)."],
                       raw=value[:64])
    if expected_type:
        expected_type = expected_type.upper().replace("-", "_")
        if expected_type in ("HASH", "SHA256", "SHA1", "MD5"):
            expected_type = "FILE_HASH"
        if expected_type in ("IPV4", "IPV6", "IP_ADDRESS"):
            expected_type = "IP"
        if expected_type not in VALIDATORS:
            return _result(False, expected_type, None, [f"Unsupported indicator type '{expected_type}'."],
                           raw=value)
        itype = expected_type
    else:
        itype = detect_indicator_type(value)
        if itype is None:
            return _result(False, None, None,
                           ["Could not recognise the indicator type (IP, domain, URL, hash, email, CVE)."],
                           raw=value)
    candidate = refang(value) if itype in ("IP", "DOMAIN") else value
    return VALIDATORS[itype](candidate)
