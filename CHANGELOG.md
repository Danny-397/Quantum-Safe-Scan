# Changelog

All notable changes to QuantumSafe are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Migration horizon — Mosca's inequality (`horizon.py`).** The risk score says
  *how much* vulnerable cryptography exists; it cannot say whether the migration
  finishes in time. `--secrecy-years X` (and optionally `--crqc-years Z`) applies
  `X + Y > Z`, where Y is estimated from the findings. Deliberately refuses to
  invent Z: there is no default, omitting it yields `no_verdict` rather than a
  guess, and the always-computable **break-even year** needs no estimate of Z at
  all. Y is a range, counted per cryptographic *family* rather than per finding
  (the design decision is paid once; call sites scale sub-linearly at
  `1 + log2(n)/2`, capped at 4×), and all six coefficients are emitted under
  `horizon.assumptions`.
- **Live TLS endpoint scanning (`tlsscan.py`, `--url`, `POST /api/v1/scan-url`).**
  Reports the negotiated key exchange, protocol and cipher for an HTTPS host.
  TLS 1.3 removed the key exchange from the cipher suite name and Python's `ssl`
  cannot read the `key_share` group (`set_groups`/`group_used` need OpenSSL 3.5+
  and Python 3.14), so the ClientHello is built by hand: offer the hybrid groups
  but a `key_share` for X25519 only, and a server preferring a hybrid must answer
  with a HelloRetryRequest naming it (RFC 8446 §4.1.3). No new dependencies;
  89–257 ms. Behind an SSRF guard — https only, ports 443/8443, every resolved
  address must be public (including the IPv4-mapped IPv6 forms of loopback,
  RFC 1918, link-local/cloud-metadata and CGNAT), rejecting on *any* private
  answer and connecting to the address that was checked rather than re-resolving.
  Rate-limited to 10/hour. Scope is one handshake — what a browser does on every
  visit — not port or vulnerability scanning.
- **Certificate chain analysis (`certchain.py`).** Every signature in the chain,
  not just the leaf: cloudflare.com's leaf is ECDSA P-256 while an intermediate
  above it is signed SHA-256 with RSA, which a leaf-only check misses. Includes a
  minimal DER/ASN.1 reader, since the signature algorithm and public key are the
  two fields `ssl.getpeercert()` omits and the package takes no `cryptography`
  dependency. Certificate findings state that the risk is *forgery of future
  certificates*, not retroactive like the key exchange; a root's self-signature
  is shown but not scored, because a root is trusted via the client's trust store.
- **Scan diffing (`diff.py`, `--baseline`, `--fail-on-new`,
  `GET /api/v1/scans/{id}/diff`).** Lets CI ratchet — tolerate an existing
  backlog, fail only when it grows, which `--fail-on-high` cannot do without
  failing every build from day one. Findings are identified *without* their line
  number, so a reformat is not reported as a fix plus a regression, with counts
  tracked per key. The verdict is driven by new findings, never the score delta:
  the score caps at 100, so a codebase already at the cap can acquire new HIGH
  findings with the number unmoved.
- **`baseline` / `fail-on-new` inputs on the GitHub Action.** A missing baseline
  file warns and skips the comparison instead of failing, so a first run works.
- **"Scan a live website" on the dashboard.** The home page exposes the TLS scan
  with the key exchange, protocol, cipher and full certificate chain rendered,
  and shows the server's own refusal reason for a rejected target.
- **Third-party origin sweep (`origins.py`, `--origins`).** A site can negotiate a
  hybrid on its own domain and still pull scripts, fonts and analytics from a dozen
  other origins over classical key exchange. Measured on `github.com`: 2 of 5
  third-party origins post-quantum, 3 classical. Produces one aggregate finding rather
  than one per origin, at MEDIUM when the page's own key exchange is fine, because a
  third-party server is not the author's to fix. A page is attacker-controlled input,
  so the SSRF guard runs on every *discovered* origin, not once on the entry URL;
  markup pointing at `169.254.169.254` is refused and recorded, never followed. Page
  size, origin count and each handshake are all bounded. No HTML dependency —
  `html.parser` is in the standard library.
- **`pqc_hybrid` and `pqc_signature` families**, with `NO_ACTION_FAMILIES`
  marking families that are reported but need no migration — so an endpoint that
  has already migrated is not billed migration effort, and a post-quantum key
  exchange is not told to consider SHA-384.

### Fixed
- **SARIF no longer invents a file and a line for endpoint findings.** They were
  emitted with `artifactLocation.uri` set to a bare host plus a bracketed suffix
  and a fabricated `startLine: 1` — schema-valid, but it would make GitHub code
  scanning annotate a file that does not exist. Endpoint findings now carry the
  real `https://host` URI, no region, and the certificate position as a
  `logicalLocation`.
- `api()` in the dashboard now attaches the HTTP status to the errors it throws,
  so a deliberate 400 refusal is shown immediately rather than sitting through a
  retry intended for a cold backend.

## [0.2.0] — 2026-07-18

### Added
- **Cross-language usage-awareness.** String/comment masking now spans all
  supported languages (previously Python-only): a lexer-style state machine
  blanks comment and string content for JS/TS, Java, C#, C/C++, Rust, Kotlin,
  Swift, PHP, and Ruby, with **import-aware** handling for Go. A
  **string-argument recovery** pass preserves genuine usages named inside a
  string (e.g. `MessageDigest.getInstance("SHA-1")`). Removes 27 labeled false
  positives (was 14, Python-only).
- **Dependency + lockfile scanning (`dependencies.py`).** Parses manifests and
  lockfiles across pip/npm/go/maven/gem (`requirements.txt`, `pyproject.toml`,
  `package.json`, `go.mod`, `pom.xml`, `Gemfile`, `package-lock.json`,
  `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `go.sum`) and flags
  known quantum-vulnerable crypto libraries with **purl** and **direct/transitive
  scope**. On by default (`--no-deps` to disable).
- **Richer CBOM.** CycloneDX output now emits dependency `library` components
  (with purl + scope) alongside algorithm crypto-assets, linked by a
  `dependencies` graph.
- **Reachability ranking (`reachability.py`).** Labels each source finding
  `reachable` / `test-example` / `unreferenced` via a conservative Python call
  graph, sorting exploitable findings above dead/example code. On by default
  (`--no-rank` to disable).
- **Call-site remediation (`remediation.py`).** Every finding carries a concrete
  before/after for drop-ins (MD5/SHA-1 → SHA-256, 3DES/RC4 → AES-256-GCM, TLS →
  1.3) or a PQC migration pointer with a language-appropriate library for
  asymmetric families; surfaced in JSON, HTML, and SARIF help text.
- **Cross-file (whole-program) taint analysis (`callgraph.py`).** The `--taint`
  pass is no longer intra-module: it builds a program-wide Python call graph by
  resolving imports (absolute, relative, unique-suffix) to qualified symbols and
  propagates crypto taint to a fixpoint across files, so a wrapper defined in one
  module and called from another (no crypto keyword at the call site) is flagged,
  with provenance naming the resolving module. Edges are only created on a
  resolved import, so same-named functions can't create phantom taint.
- **Seeded recall benchmark (`benchmark/seeded.py`).** A mutation benchmark with
  ground truth by construction — 50 real quantum-vulnerable API calls across 7
  languages that must be detected, plus 50 comment/string decoys that must not
  be. Latest run: 100% recall, 100% mutation precision.

### Changed
- Labeled benchmark expanded to 18 files (added Java/JS/Go decoys); usage-aware
  engine holds 100% precision/recall while the naive baseline drops to 49.1%.
- Test suite grows to 97 tests.

## [0.1.0]

### Added
- **Quantum module (`quantum/`):** real Qiskit implementations of Shor's
  algorithm (quantum order-finding factors N and recovers an RSA key) and
  Grover's algorithm (key-search speedup), run on a quantum simulator.
- **Post-quantum module (`pqc/`):** a from-scratch lattice-based (LWE) key
  encapsulation mechanism — the foundation of NIST ML-KEM/Kyber — implementing
  the quantum-safe replacement the scanner recommends.
- **Evaluation (`benchmark/`):** labeled precision/recall benchmark (100% on 24
  findings across 9 languages, with comment/word-boundary decoys), enforced by
  tests; scanner now skips comment-only lines to cut false positives.
- **Detection engine:** AST (Python) + regex scanning across Python, JavaScript/
  TypeScript, Java, Go, Ruby, C#, PHP, Rust, C/C++, Kotlin, and Swift.
- **Output formats:** terminal, JSON, standalone HTML, **SARIF 2.1.0**,
  **CycloneDX CBOM**, and an embeddable **SVG risk badge**.
- **False-positive controls:** inline `# quantumsafe: ignore` suppression and
  `--exclude` glob patterns.
- **Backend:** Flask REST API (auth, scans, history, overview, migration plan,
  exports), JWT + bcrypt, hashed API keys, email alerts, rate limiting,
  CORS lockdown. Free, no paywall.
- **Dashboard:** dark Bloomberg-style UI; landing page with an in-browser live
  scanner; auth, overview, scans, findings, migration, settings.
- **Ecosystem:** reusable GitHub Action + code-scanning workflow, pre-commit hook.
- **Ops:** Docker + docker-compose, Render blueprint, Vercel config.
- **Legal/compliance:** Privacy Policy, Terms of Service, signup consent,
  security disclosure policy (SECURITY.md + security.txt).
- **Quality:** 45-test pytest suite, GitHub Actions CI, demo seed script.

[0.2.0]: https://github.com/Danny-397/Quantum-Safe-Scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/Danny-397/Quantum-Safe-Scan/releases/tag/v0.1.0
