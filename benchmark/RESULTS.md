# Benchmark results

Generated from the labeled corpus in this directory via
[`evaluate.py`](evaluate.py). The corpus design and methodology are documented in
[README.md](README.md); the numbers below are reproduced by running the real
scanner, not asserted by hand.

```bash
pip install -e .
python benchmark/evaluate.py
```

---

## Precision / recall / F1

For the set of expected `(file, family)` pairs `E` and the set the scanner
detects `D`:

- **Precision** = `|E ∩ D| / |D|` — of everything flagged, how much was correct.
- **Recall** = `|E ∩ D| / |E|` — of everything that should have been flagged, how
  much was caught.
- **F1** = harmonic mean of precision and recall (a single combined figure).

| Metric            | Value                              |
|-------------------|------------------------------------|
| Files             | 12 (9 positive, 3 negative/decoy)  |
| Languages         | 9 (engine supports 11)             |
| Labeled findings  | 24                                 |
| True positives    | 24                                 |
| False positives   | 0                                  |
| False negatives   | 0                                  |
| **Precision**     | **100%**                           |
| **Recall**        | **100%**                           |
| **F1**            | **100%**                           |

The zero false-positive result holds despite deliberate decoys: crypto names that
appear only in comments (skipped, comment-only lines), and word-boundary traps
(`md5sumLabel`, `rc4legacyName`, `dsaCount`) excluded by anchored patterns.

---

## Risk distribution (labeled findings)

Derived from `labels.json` (24 findings across the positive corpus).

### By crypto family

| Family | Findings | Severity |
|--------|---------:|----------|
| RSA    | 6 | HIGH |
| MD5    | 5 | HIGH |
| SHA-256| 3 | LOW |
| ECC    | 2 | HIGH |
| SHA-1  | 2 | HIGH |
| DSA    | 1 | HIGH |
| DH     | 1 | HIGH |
| 3DES   | 1 | MEDIUM |
| RC4    | 1 | MEDIUM |
| TLS old| 1 | MEDIUM |
| AES-128| 1 | LOW |

### By severity

| Severity | Findings | Share |
|----------|---------:|------:|
| HIGH     | 17 | 71% |
| MEDIUM   | 3  | 12% |
| LOW      | 4  | 17% |

(HIGH = `rsa, ecc, dsa, dh, md5, sha1`; MEDIUM = `tls_old, 3des, rc4`;
LOW = `sha256, aes128`.)

---

## Scan performance

The detection engine is pure-Python static analysis with no network calls per
file. Practical throughput is dominated by file I/O and regex matching; the engine
skips vendor directories and files over 2 MB (e.g. minified bundles) so scan time
scales roughly linearly with the number of in-scope source files. The
reproducible measurement (scan time vs. corpus size) is produced by the graph
script below rather than quoted as a fixed number, since it depends on the host.

---

## Reproducible charts

The script in [`graphs/generate_graphs.py`](graphs/generate_graphs.py) regenerates
three figures from live data (it runs the real scanner — it does not hardcode the
numbers above):

1. **Bar chart** — vulnerabilities by crypto family.
2. **Pie chart** — HIGH / MEDIUM / LOW distribution.
3. **Line chart** — scan time vs. number of files.

```bash
pip install matplotlib
python benchmark/graphs/generate_graphs.py     # writes PNGs into benchmark/graphs/
```

`matplotlib` is intentionally **not** part of the core or CI requirements — the
chart script is an optional, standalone tool, so the main project stays
dependency-light.

---

## Honest framing

This is a **regression benchmark**, not a large-scale field study. 100% on 24
findings demonstrates the approach and guards against regressions; it is not a
claim of perfect accuracy on arbitrary code. See [README.md](README.md) and
[../TECHNICAL_OVERVIEW.md](../TECHNICAL_OVERVIEW.md) for the limitations.
