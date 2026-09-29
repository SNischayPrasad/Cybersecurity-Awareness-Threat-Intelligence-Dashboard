"""Tests 1-11 (+39): IOC syntax validation. Validation = syntax, never maliciousness."""
from backend.services.ioc_validator import defang, validate_indicator


def test_01_valid_ipv4():
    r = validate_indicator("198.51.100.25")
    assert r["valid"] and r["indicator_type"] == "IP" and r["subtype"] == "IPv4"
    assert r["normalized_value"] == "198.51.100.25"
    assert any("documentation range" in n for n in r["validation_notes"])


def test_02_invalid_ipv4():
    for bad in ("256.10.10.10", "198.51.100", "1.2.3.4.5"):
        assert not validate_indicator(bad, "IP")["valid"], bad


def test_03_valid_ipv6():
    r = validate_indicator("2001:DB8:0:0::1")
    assert r["valid"] and r["subtype"] == "IPv6"
    assert r["normalized_value"] == "2001:db8::1"  # compressed + lower-cased


def test_04_valid_domain():
    r = validate_indicator("Login-Check.INVALID.")
    assert r["valid"] and r["indicator_type"] == "DOMAIN"
    assert r["normalized_value"] == "login-check.invalid"
    assert any("reserved" in n.lower() for n in r["validation_notes"])


def test_05_invalid_domain():
    for bad in ("-bad-.invalid", "nodot", "exa mple.com", "a..example.com", "example.c0m1"):
        assert not validate_indicator(bad, "DOMAIN")["valid"], bad


def test_06_valid_url_including_defanged_input():
    r = validate_indicator("hxxps://login-check[.]invalid/verify/session")
    assert r["valid"] and r["indicator_type"] == "URL"
    assert r["normalized_value"] == "https://login-check.invalid/verify/session"
    assert any("NOT visited" in n for n in r["validation_notes"])
    assert not validate_indicator("javascript:alert(1)", "URL")["valid"]


def test_07_valid_md5_format_hash():
    r = validate_indicator("d41d8cd98f00b204e9800998ecf8427e")
    assert r["valid"] and r["indicator_type"] == "FILE_HASH" and r["subtype"] == "MD5"


def test_08_valid_sha1_format_hash():
    r = validate_indicator("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
    assert r["valid"] and r["subtype"] == "SHA1"
    assert r["normalized_value"] == r["normalized_value"].lower()


def test_09_valid_sha256_format_hash():
    r = validate_indicator("a" * 64)
    assert r["valid"] and r["subtype"] == "SHA256"
    assert not validate_indicator("z" * 64, "FILE_HASH")["valid"]  # not hex
    assert not validate_indicator("a" * 63, "FILE_HASH")["valid"]  # wrong length


def test_10_valid_cve_format():
    r = validate_indicator("cve-2099-0002")
    assert r["valid"] and r["indicator_type"] == "CVE" and r["normalized_value"] == "CVE-2099-0002"
    assert any("SYNTHETIC" in n for n in r["validation_notes"])


def test_11_invalid_cve_format():
    for bad in ("CVE-99-1234", "CVE-2099-12", "CVE2099-12345", "CVE-2099-ABCD"):
        assert not validate_indicator(bad, "CVE")["valid"], bad


def test_39_defang_display():
    assert defang("https://login-check.invalid/x") == "hxxps://login-check[.]invalid/x"
    assert defang("198.51.100.25") == "198[.]51[.]100[.]25"
    assert defang("a" * 64) == "a" * 64  # hashes unchanged
