"""Tests for the interprocedural data-flow (taint) analysis."""

from quantumsafe.scanner import RISK_HIGH, scan_path


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


WRAPPED = (
    "import hashlib\n"
    "\n"
    "def _legacy_digest(data):\n"
    "    return hashlib.md5(data).hexdigest()\n"
    "\n"
    "def sign_request(payload):\n"
    "    return _legacy_digest(payload)\n"
    "\n"
    "token = sign_request(body)\n"
)


def test_taint_off_by_default_does_not_flag_wrapper_call_site(tmp_path):
    _write(tmp_path, "wrap.py", WRAPPED)
    findings = scan_path(str(tmp_path))
    # Only the direct hashlib.md5 line (4) is caught without taint.
    lines = {f.line_number for f in findings if f.family == "md5"}
    assert lines == {4}


def test_taint_flags_wrapper_and_call_site(tmp_path):
    _write(tmp_path, "wrap.py", WRAPPED)
    findings = scan_path(str(tmp_path), taint=True)
    md5 = [f for f in findings if f.family == "md5"]
    lines = {f.line_number for f in md5}
    # Direct primitive (4), one-hop wrapper call (7), and the outer call site (9).
    assert {4, 7, 9} <= lines
    indirect = [f for f in md5 if f.confidence == "indirect"]
    assert indirect, "expected indirect findings from data-flow analysis"
    assert all(f.risk_level == RISK_HIGH for f in indirect)
    assert any("via" in f.algorithm for f in indirect)


def test_taint_does_not_double_flag_direct_keyword_lines(tmp_path):
    # The call site literally names md5, so the direct scan owns it and taint
    # must not add a second, overlapping finding on the same line.
    _write(tmp_path, "d.py",
           "import hashlib\n"
           "def make_md5(x):\n"
           "    return hashlib.md5(x)\n"
           "y = make_md5(data)  # md5 in the call-site text\n")
    findings = scan_path(str(tmp_path), taint=True)
    line4 = [f for f in findings if f.line_number == 4 and f.family == "md5"]
    assert not any(f.confidence == "indirect" for f in line4)


def test_taint_no_false_positive_on_safe_wrapper(tmp_path):
    _write(tmp_path, "safe.py",
           "import hashlib\n"
           "def strong_digest(data):\n"
           "    return hashlib.sha3_256(data).hexdigest()\n"
           "value = strong_digest(payload)\n")
    findings = scan_path(str(tmp_path), taint=True)
    assert not [f for f in findings if f.confidence == "indirect"]
