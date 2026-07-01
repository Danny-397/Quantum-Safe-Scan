"""Tests for the core detection engine."""

import pytest

from quantumsafe.scanner import (
    RISK_HIGH,
    RISK_LOW,
    _validate_repo_url,
    scan_path,
)


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_detects_rsa_md5_sha1_in_python(tmp_path):
    _write(tmp_path, "crypto.py",
           "import hashlib\n"
           "from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
           "h = hashlib.md5(b'x')\n"
           "g = hashlib.sha1(b'y')\n")
    findings = scan_path(str(tmp_path))
    algos = {f.algorithm for f in findings}
    assert any("RSA" in a for a in algos)
    assert "MD5" in algos
    assert "SHA-1" in algos
    assert all(f.risk_level == RISK_HIGH for f in findings if f.algorithm in ("MD5", "SHA-1"))


def test_detects_across_languages(tmp_path):
    _write(tmp_path, "app.js", "const k = crypto.generateKeyPairSync('rsa', {});\n")
    _write(tmp_path, "Main.java", 'MessageDigest.getInstance("SHA-1");\n')
    _write(tmp_path, "main.go", 'import "crypto/ecdsa"\n')
    _write(tmp_path, "x.rb", "Digest::MD5.hexdigest('a')\n")
    families = {f.family for f in scan_path(str(tmp_path))}
    assert {"rsa", "sha1", "ecc", "md5"} <= families


def test_detects_extended_languages(tmp_path):
    _write(tmp_path, "a.cs", "var rsa = new RSACryptoServiceProvider(2048);\nvar md5 = MD5.Create();\n")
    _write(tmp_path, "b.php", "<?php $k = openssl_pkey_new(); $h = md5($data); ?>\n")
    _write(tmp_path, "c.rs", "use rsa::RsaPrivateKey;\nlet d = Sha1::new();\n")
    _write(tmp_path, "d.swift", "let digest = Insecure.MD5.hash(data: data)\n")
    families = {f.family for f in scan_path(str(tmp_path))}
    assert "rsa" in families
    assert "md5" in families
    assert "sha1" in families


def test_deduplicates_per_line_and_family(tmp_path):
    # This line matches the generic RSA rule, the RSA-2048 rule, AND the AST rule.
    _write(tmp_path, "c.py",
           "from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "k = rsa.generate_private_key(public_exponent=3, key_size=2048)\n")
    findings = scan_path(str(tmp_path))
    line2 = [f for f in findings if f.line_number == 2 and f.family == "rsa"]
    assert len(line2) == 1, f"expected 1 deduped rsa finding, got {len(line2)}"


def test_clean_code_has_no_findings(tmp_path):
    _write(tmp_path, "ok.py", "def add(a, b):\n    return a + b\n")
    assert scan_path(str(tmp_path)) == []


def test_minified_files_are_skipped(tmp_path):
    # Same matching content: the normal file is flagged, the minified ones are not
    # (machine-generated bundles are skipped to avoid false positives).
    snippet = "const k = crypto.createCipheriv('rc4', key, iv);\n"
    _write(tmp_path, "net.js", snippet)              # detected
    _write(tmp_path, "net.min.js", snippet)          # skipped by name
    _write(tmp_path, "vendor-min.js", snippet)       # skipped by name
    _write(tmp_path, "app.bundle.js", snippet)       # skipped by name
    _write(tmp_path, "packed.js", "x();" + "a" * 2100 + snippet)  # skipped: huge line
    files = {f.file_path for f in scan_path(str(tmp_path))}
    assert files == {"net.js"}, f"expected only net.js, got {files}"


def test_python_string_and_comment_matches_are_ignored(tmp_path):
    # Crypto keywords inside docstrings, log messages, and exception strings are
    # documentation, not usage, and must not be flagged. Real usage in the same
    # file is still detected by the AST engine.
    _write(tmp_path, "svc.py",
           "import hashlib\n"
           "def rotate():\n"
           '    """This service no longer uses MD5 or RSA or ECDSA."""\n'
           '    logger.info("Disabling RSA and DSA fallback")\n'
           '    raise ValueError("SHA-1 is not allowed")\n'
           '    return hashlib.md5(b"x")   # real usage, still caught\n')
    algos = {f.algorithm for f in scan_path(str(tmp_path))}
    assert algos == {"MD5"}, f"expected only the real MD5 usage, got {algos}"


def test_string_masking_is_what_removes_false_positives(tmp_path):
    # Without masking (naive line regex) the same decoy yields false positives;
    # masking is what removes them. This guards the precision improvement.
    _write(tmp_path, "d.py",
           "def f():\n"
           '    """uses RSA and MD5"""\n'
           '    log("ECDSA here")\n')
    assert scan_path(str(tmp_path)) == []
    naive = {f.algorithm for f in scan_path(str(tmp_path), mask_python_strings=False)}
    assert {"RSA", "MD5", "ECDSA"} <= naive


def test_findings_carry_confidence(tmp_path):
    _write(tmp_path, "c.py", "from x import rsa\nk = rsa.generate_private_key()\n")
    findings = scan_path(str(tmp_path))
    assert findings
    assert all(f.confidence in ("high", "medium") for f in findings)
    assert any(f.confidence == "high" for f in findings)


def test_low_risk_classification(tmp_path):
    _write(tmp_path, "s.py", "import hashlib\nh = hashlib.sha256(b'x')\n")
    findings = scan_path(str(tmp_path))
    assert any(f.algorithm == "SHA-256" and f.risk_level == RISK_LOW for f in findings)


def test_findings_are_enriched_with_recommendations(tmp_path):
    _write(tmp_path, "c.py", "from x import rsa\nrsa.generate_private_key()\n")
    findings = scan_path(str(tmp_path))
    assert findings
    f = findings[0]
    assert f.recommendation and f.nist_reference and f.complexity


@pytest.mark.parametrize("bad_url", [
    "https://evil.com/a/b",
    "http://github.com/a/b",
    "https://github.com/a/b/../../c",
    "git@github.com:a/b.git",
    "ftp://github.com/a/b",
])
def test_repo_url_validation_rejects_bad_urls(bad_url):
    with pytest.raises(ValueError):
        _validate_repo_url(bad_url)


def test_repo_url_validation_accepts_good_url():
    assert _validate_repo_url("https://github.com/org/app") == "https://github.com/org/app"
