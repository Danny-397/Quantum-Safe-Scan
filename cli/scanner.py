"""Core cryptographic vulnerability detection.

Two complementary engines:

* A **regex engine** runs over Python, JavaScript/TypeScript, Java, Go and Ruby
  source files, matching known quantum-vulnerable algorithm usage.
* An **AST engine** parses Python files with the standard ``ast`` module to find
  ``hashlib`` / ``cryptography`` / ``pycryptodome`` usage precisely, avoiding the
  false positives a regex would hit inside comments.

Findings from both engines are merged and de-duplicated per (file, line, family)
so a single line of code never inflates the risk score twice.
"""

from __future__ import annotations

import ast
import io
import os
import re
import shutil
import subprocess
import tempfile
import tokenize
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .recommender import recommend

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"


@dataclass
class Finding:
    file_path: str
    line_number: int
    algorithm: str
    risk_level: str
    why: str
    family: str
    recommendation: str = ""
    nist_reference: str = ""
    complexity: str = ""
    snippet: str = ""
    # "high"  = precise AST match, or a match sitting on a real call/import line.
    # "medium" = a regex keyword match on a code line with no obvious usage signal.
    confidence: str = "medium"

    def enrich(self) -> "Finding":
        rec = recommend(self.family)
        self.recommendation = rec.replacement
        self.nist_reference = rec.nist_reference
        self.complexity = rec.complexity
        if not self.why:
            self.why = rec.detail
        return self

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "algorithm": self.algorithm,
            "risk_level": self.risk_level,
            "why": self.why,
            "family": self.family,
            "recommendation": self.recommendation,
            "nist_reference": self.nist_reference,
            "complexity": self.complexity,
            "snippet": self.snippet,
            "confidence": self.confidence,
        }


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #


@dataclass
class Rule:
    family: str
    algorithm: str
    risk: str
    why: str
    pattern: re.Pattern
    languages: set[str] | None = None  # None == all supported languages


def _r(
    family: str,
    algorithm: str,
    risk: str,
    why: str,
    regex: str,
    languages: set[str] | None = None,
) -> Rule:
    return Rule(family, algorithm, risk, why, re.compile(regex, re.IGNORECASE), languages)


# Order matters only for readability; de-duplication picks the highest risk per
# family per line. Patterns favor word boundaries to limit false positives.
RULES: list[Rule] = [
    # ---- HIGH ----
    _r("rsa", "RSA-2048", RISK_HIGH,
       "RSA-2048 key usage; broken by Shor's algorithm on a quantum computer.",
       r"\brsa[\s_\-]?2048\b|\b2048\b\s*(?:bit)?\s*rsa\b"),
    _r("rsa", "RSA-4096", RISK_HIGH,
       "RSA-4096 key usage; larger keys do not help against Shor's algorithm.",
       r"\brsa[\s_\-]?4096\b|\b4096\b\s*(?:bit)?\s*rsa\b"),
    _r("rsa", "RSA", RISK_HIGH,
       "RSA public-key cryptography is broken by Shor's algorithm.",
       r"\bRSA\b|generate_private_key.*rsa|crypto\.generateKeyPair(?:Sync)?\(\s*['\"]rsa['\"]|rsa\.GenerateKey|OpenSSL::PKey::RSA|RSACryptoServiceProvider|openssl_pkey_new|RsaKeyParameters"),
    _r("ecc", "ECDSA", RISK_HIGH,
       "ECDSA signatures are broken by Shor's algorithm.",
       r"\bECDSA\b|ecdsa\b"),
    _r("ecc", "ECDH", RISK_HIGH,
       "ECDH key exchange is broken by Shor's algorithm.",
       r"\bECDH\b|ecdh\b"),
    _r("ecc", "ECC", RISK_HIGH,
       "Elliptic-curve cryptography is broken by Shor's algorithm.",
       r"\bECC\b|elliptic[\s_\-]?curve|EllipticCurve|ec\.generate_private_key|crypto/ecdsa|secp256[rk]1|prime256v1|NIST P-256"),
    _r("dsa", "DSA", RISK_HIGH,
       "DSA signatures are broken by Shor's algorithm.",
       r"\bDSA\b|dsa\.generate_private_key|crypto/dsa"),
    _r("dh", "Diffie-Hellman", RISK_HIGH,
       "Classic Diffie-Hellman key exchange is broken by Shor's algorithm.",
       r"\bDiffie[\s\-]?Hellman\b|\bDH\b|dh\.generate_parameters|DHParameterSpec|crypto/dh"),
    _r("md5", "MD5", RISK_HIGH,
       "MD5 is collision-broken and weakened by Grover's algorithm.",
       r"\bMD5\b|hashlib\.md5|md5\(|md5_file|crypto\.createHash\(\s*['\"]md5['\"]|MessageDigest\.getInstance\(\s*['\"]MD5['\"]|Digest::MD5"),
    _r("sha1", "SHA-1", RISK_HIGH,
       "SHA-1 is collision-broken and weakened by Grover's algorithm.",
       r"\bSHA[\s\-_]?1\b|hashlib\.sha1|sha1\(|sha1_file|crypto\.createHash\(\s*['\"]sha1['\"]|MessageDigest\.getInstance\(\s*['\"]SHA-?1['\"]|Digest::SHA1"),

    # ---- MEDIUM ----
    _r("tls_old", "TLS 1.0", RISK_MEDIUM,
       "TLS 1.0 is deprecated and uses quantum-vulnerable key exchange.",
       r"TLSv1(?:\.0)?\b|PROTOCOL_TLSv1\b|TLS1_0|SSLv3|TLSv1_method"),
    _r("tls_old", "TLS 1.1", RISK_MEDIUM,
       "TLS 1.1 is deprecated and uses quantum-vulnerable key exchange.",
       r"TLSv1\.1\b|PROTOCOL_TLSv1_1\b|TLS1_1|TLSv1_1_method"),
    _r("3des", "3DES / Triple DES", RISK_MEDIUM,
       "3DES is deprecated; Grover's algorithm halves its effective strength.",
       r"\b3DES\b|Triple[\s_\-]?DES\b|DESede|DES3|TripleDES|des_ede3"),
    _r("rc4", "RC4", RISK_MEDIUM,
       "RC4 is insecure and prohibited in TLS.",
       r"\bRC4\b|\bARC4\b|Cipher\.getInstance\(\s*['\"]RC4['\"]"),
    _r("rsa", "RSA <2048 (weak key size)", RISK_MEDIUM,
       "RSA key size below 2048 bits is weak even against classical attacks.",
       r"key_size\s*=\s*(?:512|768|1024)\b|RSA.{0,12}\b(?:512|768|1024)\b|\b(?:512|768|1024)\b.{0,12}RSA"),

    # ---- LOW ----
    _r("sha256", "SHA-256", RISK_LOW,
       "Grover's algorithm weakens SHA-256 to ~128-bit security (still safe).",
       r"\bSHA[\s\-_]?256\b|hashlib\.sha256|crypto\.createHash\(\s*['\"]sha256['\"]|Digest::SHA256"),
    _r("aes128", "AES-128", RISK_LOW,
       "Grover's algorithm halves AES-128 to ~64-bit security.",
       r"\bAES[\s\-_]?128\b|AES.{0,8}\b128\b"),
    _r("tls12", "TLS 1.2", RISK_LOW,
       "TLS 1.2 is acceptable but still relies on classical key exchange.",
       r"TLSv1\.2\b|PROTOCOL_TLSv1_2\b|TLS1_2|TLSv1_2_method"),
]

# Risk ranking used when collapsing multiple matches in the same family/line.
_RISK_RANK = {RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1}

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
}

_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", "site-packages", ".idea", ".vscode",
}

_MAX_FILE_BYTES = 2_000_000  # skip very large/minified files

# Minified / bundled assets are machine-generated, not first-party source. A
# "crypto" match inside a packed line is almost always a false positive (e.g. the
# substring "rc4"/"sha1" inside a minified library), so we skip them. Detected by
# name OR by a single absurdly long line (only minified/generated code does that).
_MINIFIED_RE = re.compile(r"(?:[.\-]min)\.(?:js|mjs|cjs)$|\.bundle\.js$", re.IGNORECASE)
_MINIFIED_MAX_LINE = 2000


def _looks_minified(name: str, lines: list[str]) -> bool:
    if _MINIFIED_RE.search(name):
        return True
    return any(len(ln) > _MINIFIED_MAX_LINE for ln in lines)


# --------------------------------------------------------------------------- #
# AST engine (Python only)
# --------------------------------------------------------------------------- #

_AST_HASH = {
    "md5": ("md5", "MD5", RISK_HIGH, "MD5 is collision-broken and weakened by Grover's algorithm."),
    "sha1": ("sha1", "SHA-1", RISK_HIGH, "SHA-1 is collision-broken and weakened by Grover's algorithm."),
    "sha256": ("sha256", "SHA-256", RISK_LOW, "Grover's algorithm weakens SHA-256 to ~128-bit security (still safe)."),
}

_AST_ASYM = {
    "rsa": ("rsa", "RSA", RISK_HIGH, "RSA public-key cryptography is broken by Shor's algorithm."),
    "ec": ("ecc", "ECC", RISK_HIGH, "Elliptic-curve cryptography is broken by Shor's algorithm."),
    "dsa": ("dsa", "DSA", RISK_HIGH, "DSA signatures are broken by Shor's algorithm."),
    "dh": ("dh", "Diffie-Hellman", RISK_HIGH, "Classic Diffie-Hellman key exchange is broken by Shor's algorithm."),
}


def _ast_scan_python(source: str, rel_path: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings  # fall back to regex engine only

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        dotted = _dotted_name(func)
        if not dotted:
            continue
        low = dotted.lower()
        lineno = getattr(node, "lineno", 0)
        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

        # hashlib.md5() / hashlib.sha1() / hashlib.sha256()
        for key, (family, algo, risk, why) in _AST_HASH.items():
            if low.endswith("hashlib." + key) or low == key:
                findings.append(Finding(rel_path, lineno, algo, risk, why, family, snippet=snippet, confidence="high"))

        # hashlib.new("md5") style
        if low.endswith("hashlib.new") and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                name = arg0.value.lower().replace("-", "")
                if name in _AST_HASH:
                    family, algo, risk, why = _AST_HASH[name]
                    findings.append(Finding(rel_path, lineno, algo, risk, why, family, snippet=snippet, confidence="high"))

        # asymmetric key generation: rsa.generate_private_key, ec.generate_private_key, etc.
        for key, (family, algo, risk, why) in _AST_ASYM.items():
            if re.search(rf"\b{key}\.generate_(?:private_key|parameters)$", low):
                findings.append(Finding(rel_path, lineno, algo, risk, why, family, snippet=snippet, confidence="high"))
    return findings


def _dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted attribute/name path from an AST node."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


# --------------------------------------------------------------------------- #
# Regex engine (all languages)
# --------------------------------------------------------------------------- #


# Line-comment markers per language, used to skip comment-only lines (a major
# source of false positives — a `# TODO: drop MD5` line shouldn't be flagged).
_LINE_COMMENT = {
    "python": ("#",), "ruby": ("#",),
    "javascript": ("//", "/*", "*"), "java": ("//", "/*", "*"),
    "go": ("//", "/*", "*"), "c": ("//", "/*", "*"), "cpp": ("//", "/*", "*"),
    "csharp": ("//", "/*", "*"), "rust": ("//", "/*", "*"),
    "kotlin": ("//", "/*", "*"), "swift": ("//", "/*", "*"),
    "php": ("#", "//", "/*", "*"),
}


def _is_comment_line(line: str, lang: str) -> bool:
    s = line.lstrip()
    return bool(s) and s.startswith(_LINE_COMMENT.get(lang, ()))


# Token types whose text is *content*, not code, and should be masked out before
# the Python regex pass (string literals, comments, and — on 3.12+ — the literal
# segments of f-strings; the ``{expr}`` interpolations stay as real code).
_PY_MASK_TYPES = {tokenize.STRING, tokenize.COMMENT}
for _name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
    _t = getattr(tokenize, _name, None)
    if _t is not None:
        _PY_MASK_TYPES.add(_t)


def _mask_python_strings(source: str, lines: list[str]) -> list[str]:
    """Blank the characters inside Python string/comment tokens (positions kept).

    This is a lightweight, precise form of usage-awareness: a keyword like "RSA"
    or "MD5" sitting inside a docstring, log message, or exception string is
    documentation, not usage, so it should not be flagged by the regex engine.
    Genuine string-argument usage (e.g. ``hashlib.new("md5")``) is still caught
    by the AST engine, which runs on the original source. Falls back to the
    unmodified lines if the file does not tokenize.
    """
    masked = [list(ln) for ln in lines]
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type not in _PY_MASK_TYPES:
                continue
            (srow, scol), (erow, ecol) = tok.start, tok.end
            for row in range(srow, erow + 1):
                idx = row - 1
                if not (0 <= idx < len(masked)):
                    continue
                buf = masked[idx]
                start = scol if row == srow else 0
                end = ecol if row == erow else len(buf)
                for c in range(start, min(end, len(buf))):
                    buf[c] = " "
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return lines
    return ["".join(buf) for buf in masked]


# A match sits on "real usage" when its line looks like a call, an import, or a
# known crypto constructor — as opposed to a bare keyword mention.
_USAGE_SIGNAL = re.compile(
    r"\w\s*\(|^\s*(?:import|from|require|use|using|package|#include)\b"
    r"|getInstance|createHash|generateKey|Cipher|PKey|new\s+\w",
    re.IGNORECASE,
)


def _confidence_for(line: str) -> str:
    return "high" if _USAGE_SIGNAL.search(line) else "medium"


def _regex_scan(match_lines: list[str], orig_lines: list[str],
                lang: str, rel_path: str) -> list[Finding]:
    """Scan ``match_lines`` (possibly string-masked) but report the original code."""
    findings: list[Finding] = []
    for i, raw in enumerate(match_lines, start=1):
        line = raw.rstrip("\n")
        if not line.strip() or _is_comment_line(line, lang):
            continue
        orig = orig_lines[i - 1].strip() if i - 1 < len(orig_lines) else line.strip()
        for rule in RULES:
            if rule.languages and lang not in rule.languages:
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(rel_path, i, rule.algorithm, rule.risk, rule.why,
                            rule.family, snippet=orig, confidence=_confidence_for(orig))
                )
    return findings


# --------------------------------------------------------------------------- #
# De-duplication
# --------------------------------------------------------------------------- #


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per (file, line, family), preferring the highest risk."""
    best: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.file_path, f.line_number, f.family)
        cur = best.get(key)
        if cur is None or _RISK_RANK[f.risk_level] > _RISK_RANK[cur.risk_level]:
            best[key] = f
    out = list(best.values())
    out.sort(key=lambda f: (f.file_path, f.line_number, -_RISK_RANK[f.risk_level]))
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def scan_file(abs_path: str, rel_path: str, mask_python_strings: bool = True,
              taint: bool = False) -> list[Finding]:
    ext = os.path.splitext(abs_path)[1].lower()
    lang = EXT_TO_LANG.get(ext)
    if lang is None:
        return []
    try:
        if os.path.getsize(abs_path) > _MAX_FILE_BYTES:
            return []
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
    except (OSError, UnicodeError):
        return []

    lines = source.splitlines()
    if _looks_minified(os.path.basename(abs_path), lines):
        return []
    # Python: mask string/comment content so the regex engine ignores keywords in
    # docstrings/log strings; the AST engine still runs on the original source.
    if lang == "python" and mask_python_strings:
        match_lines = _mask_python_strings(source, lines)
    else:
        match_lines = lines
    findings = _regex_scan(match_lines, lines, lang, rel_path)
    if lang == "python":
        findings += _ast_scan_python(source, rel_path, lines)
        if taint:
            # Interprocedural data-flow pass: crypto reached through wrappers.
            from .taint import taint_scan_python
            findings += taint_scan_python(source, rel_path, lines)

    # Honor inline suppressions: a line containing "quantumsafe: ignore".
    if findings:
        findings = [
            f for f in findings
            if not (0 < f.line_number <= len(lines) and _SUPPRESS_RE.search(lines[f.line_number - 1]))
        ]
    return _dedupe(findings)


# Inline suppression marker, e.g.  key = rsa.generate(...)  # quantumsafe: ignore
_SUPPRESS_RE = re.compile(r"quantumsafe:\s*ignore", re.IGNORECASE)


def _is_excluded(rel_path: str, patterns: list[str] | None) -> bool:
    if not patterns:
        return False
    import fnmatch
    return any(fnmatch.fnmatch(rel_path, pat) for pat in patterns)


def scan_path(path: str, exclude: list[str] | None = None,
              mask_python_strings: bool = True, taint: bool = False) -> list[Finding]:
    """Recursively scan a local directory (or single file) for vulnerabilities.

    ``exclude`` is an optional list of glob patterns (matched against the path
    relative to ``path``, using forward slashes) to skip. ``mask_python_strings``
    (default on) enables the string/comment-aware pass; set it False to measure
    the naive line-regex baseline (used by the benchmark). ``taint`` (default
    off) enables the experimental interprocedural data-flow pass that also flags
    quantum-vulnerable crypto reached through Python wrapper functions.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")

    findings: list[Finding] = []
    if os.path.isfile(path):
        findings = scan_file(path, os.path.basename(path), mask_python_strings, taint)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in files:
                abs_path = os.path.join(root, name)
                rel_path = os.path.relpath(abs_path, path).replace(os.sep, "/")
                if _is_excluded(rel_path, exclude):
                    continue
                findings.extend(scan_file(abs_path, rel_path, mask_python_strings, taint))

    findings = _dedupe(findings)
    for f in findings:
        f.enrich()
    return findings


_GITHUB_RE = re.compile(r"^https://(www\.)?github\.com/[\w.\-]+/[\w.\-]+/?$")


def _validate_repo_url(url: str) -> str:
    """Allow only well-formed public https GitHub URLs (no SSH, no traversal)."""
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise ValueError("Only https://github.com/<org>/<repo> URLs are supported.")
    if ".." in url or " " in url:
        raise ValueError("Invalid repository URL.")
    if not _GITHUB_RE.match(url):
        raise ValueError("Repository URL must look like https://github.com/<org>/<repo>.")
    return url


def scan_repo(url: str, exclude: list[str] | None = None, taint: bool = False) -> list[Finding]:
    """Shallow-clone a public GitHub repo to a temp dir, scan it, then clean up."""
    url = _validate_repo_url(url)
    if shutil.which("git") is None:
        raise RuntimeError("git is required to scan remote repositories but was not found on PATH.")

    tmp = tempfile.mkdtemp(prefix="quantumsafe_")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, tmp],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone repository: {result.stderr.strip()}")
        return scan_path(tmp, exclude=exclude, taint=taint)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
